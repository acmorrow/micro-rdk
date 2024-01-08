// Support for HC-SR04 style ultrasonic ranging modules. See
// https://cdn.sparkfun.com/datasheets/Sensors/Proximity/HCSR04.pdf.

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use crate::{
    common::{
        board::BoardType,
        config::{AttributeError, ConfigType},
        registry::{self, ComponentRegistry, Dependency},
        sensor::{
            GenericReadingsResult, Readings, Sensor, SensorResult, SensorT, SensorType,
            TypedReadingsResult,
        },
        status::Status,
    },
    google, DoCommand,
};

use esp_idf_hal::{
    delay::TickType,
    gpio::{
        enable_isr_service, init_isr_alloc_flags, AnyIOPin, Input, InterruptType, Output,
        PinDriver, Pull,
    },
    task::notification::{Notification, Notifier},
};

use esp_idf_sys::{esp, gpio_isr_handler_add, gpio_isr_handler_remove};

pub(crate) fn register_models(registry: &mut ComponentRegistry) {
    if registry
        .register_sensor("ultrasonic", &HCSR04Sensor::from_config)
        .is_err()
    {
        log::error!("HCSR04Sensor is already registered");
    }
}

struct IsrSharedState {
    // The state machine used to track interrupts and compute the
    // length of the echo pulse. It holds one of the following values:
    //
    // 0: Starting state, ready to take a reading
    // i64 > 0: Millisecond timestamp of first edge of echo signal
    timestamp: AtomicI64,

    // The channel the ISR will use to communicate results back to waiters.
    notifier: Arc<Notifier>,
}

#[derive(DoCommand)]
pub struct HCSR04Sensor {
    // We require a board in order to ensure that ISR setup has completed
    _board: BoardType,

    // The PinDriver to control the pin that triggers issuing a pulse.
    trigger_pin: PinDriver<'static, AnyIOPin, Output>,

    // The PinDriver used to listen for digital interrupts and measure
    // the length of the echo pulse.
    echo_interrupt_pin: PinDriver<'static, AnyIOPin, Input>,

    // How long we will wait for an echo pulse before concluding that there is no
    // obstacle in range. Defaults to 50ms.
    timeout: Duration,

    // The notification channel used to wait on a result being posted from the ISR.
    interrupt_notification: Notification,

    // State which we share with the ISR.
    isr_shared_state: Arc<IsrSharedState>,
}

impl HCSR04Sensor {
    pub fn from_config(cfg: ConfigType, deps: Vec<Dependency>) -> anyhow::Result<SensorType> {
        let board = registry::get_board_from_dependencies(deps).ok_or(anyhow::anyhow!(
            "HCSR04Sensor: failed to get board from dependencies"
        ))?;

        let trigger_pin = cfg.get_attribute::<i32>("trigger_pin").map_err(|e| {
            anyhow::anyhow!(
                "HCSR04Sensor: failed to get `trigger_pin from configuration`: {:?}",
                e
            )
        })?;

        let echo_interrupt_pin = cfg
            .get_attribute::<i32>("echo_interrupt_pin")
            .map_err(|e| {
                anyhow::anyhow!(
                    "HCSR04Sensor: failed to get `echo_interrupt_pin` from configuration: {:?}",
                    e
                )
            })?;

        let timeout = cfg.get_attribute::<u32>("timeout_ms").map_or_else(
            |e| match e {
                AttributeError::KeyNotFound(_) => Ok(None),
                _ => Err(anyhow::anyhow!(
                    "HCSR04Sensor: error handling `timeout_ms` value: {:?}",
                    e
                )),
            },
            |v| Ok(Some(Duration::from_millis(v as u64))),
        )?;

        Ok(Arc::new(Mutex::new(HCSR04Sensor::new(
            board,
            trigger_pin,
            echo_interrupt_pin,
            timeout,
        )?)))
    }

    fn new(
        board: BoardType,
        trigger_pin: i32,
        echo_interrupt_pin: i32,
        timeout: Option<Duration>,
    ) -> anyhow::Result<HCSR04Sensor> {
        // TODO: Move this into micro-rdk and unify with pin.rs
        init_isr_alloc_flags(esp_idf_hal::interrupt::InterruptType::Iram.into());
        enable_isr_service()?;

        let notification = Notification::new();
        let notifier = notification.notifier();

        let mut sensor = Self {
            _board: board,
            trigger_pin: PinDriver::output(unsafe { AnyIOPin::new(trigger_pin) })?,
            echo_interrupt_pin: PinDriver::input(unsafe { AnyIOPin::new(echo_interrupt_pin) })?,
            timeout: timeout.unwrap_or(Duration::from_millis(50)),
            interrupt_notification: notification,
            isr_shared_state: Arc::new(IsrSharedState {
                timestamp: 0.into(),
                notifier,
            }),
        };

        sensor.echo_interrupt_pin.set_pull(Pull::Down)?;

        // Start the trigger pin high: the pulse is sent on the
        // falling edge, so we can just go low immediately in
        // `get_readings` to send it. As long as we don't get another
        // `get_readings` request within 10us of the prior one
        // completing, the pin will be high long enough to trigger the
        // pulse.
        sensor.trigger_pin.set_high()?;

        sensor
            .echo_interrupt_pin
            .set_interrupt_type(InterruptType::AnyEdge)?;

        unsafe {
            esp!(gpio_isr_handler_add(
                echo_interrupt_pin,
                Some(Self::subscription_interrupt),
                Arc::as_ptr(&sensor.isr_shared_state) as *mut _,
            ))?;
        }

        Ok(sensor)
    }

    #[inline(always)]
    #[link_section = ".iram1.intr_srv"]
    unsafe extern "C" fn subscription_interrupt(arg: *mut core::ffi::c_void) {
        let arg: &mut IsrSharedState = &mut *(arg as *mut _);
        let when = esp_idf_sys::esp_timer_get_time();
        match arg
            .timestamp
            .compare_exchange(0, when, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // Initial edge: timestamp gets stored.
            }
            Err(prior) => {
                // Terminal edge: notify the waiter if we can convert
                // the computed duration into a non-zero u32. If we
                // don't notify, the waiter will time out and return
                // an error, and the state machine will be reset on
                // the next `get_readings` call.
                if let Ok(delta) = u32::try_from(when - prior) {
                    if let Some(nz) = NonZeroU32::new(delta) {
                        arg.notifier.notify_and_yield(nz);
                    }
                }
            }
        }
    }
}

impl Drop for HCSR04Sensor {
    fn drop(&mut self) {
        let pin = self.echo_interrupt_pin.pin();
        if let Err(error) = unsafe { esp!(gpio_isr_handler_remove(pin)) } {
            log::warn!(
                "HCSR04Sensor: failed to remove interrupt handler for pin {}: {}",
                pin,
                error
            )
        }
    }
}

impl Sensor for HCSR04Sensor {}

impl Readings for HCSR04Sensor {
    fn get_generic_readings(&mut self) -> anyhow::Result<GenericReadingsResult> {
        Ok(self
            .get_readings()?
            .into_iter()
            .map(|v| (v.0, SensorResult::<f64> { value: v.1 }.into()))
            .collect())
    }
}

impl SensorT<f64> for HCSR04Sensor {
    fn get_readings(&mut self) -> anyhow::Result<TypedReadingsResult<f64>> {
        // If the echo pin is already high for some reason, the state machine
        // won't work correctly.
        if self.echo_interrupt_pin.is_high() {
            anyhow::bail!("HCSR04Sensor: echo pin is high before trigger sent")
        }

        // Reset the state machine: store zero to unlock the first
        // compare_exchange in the ISR, and consume any pending
        // notification that we may have missed on a prior timeout.
        self.isr_shared_state.timestamp.store(0, Ordering::Release);
        let _ = self.interrupt_notification.wait(0);

        // Drive the pin low to trigger the pulse, and ensure we put
        // it back to high after our wait.
        let trigger_pin = &mut self.trigger_pin;
        trigger_pin.set_low()?;
        defer! {
            let _ = trigger_pin.set_high();
        }

        // Wait (up to timeout) for a notification from the
        // ISR. Convert any result from the notification into a
        // distance.
        match self
            .interrupt_notification
            .wait(TickType::from(self.timeout).as_millis_u32())
        {
            Some(delta) => {
                let distance = delta.get() as f64 / 58.0 / 100.0;
                Ok(HashMap::from([("distance".to_string(), distance)]))
            }
            _ => {
                anyhow::bail!(
                    "HCSR04Sensor: no echo heard after {:?}; nearest obstacle may be out of range",
                    self.timeout,
                )
            }
        }
    }
}

impl Status for HCSR04Sensor {
    fn get_status(&self) -> anyhow::Result<Option<google::protobuf::Struct>> {
        Ok(Some(google::protobuf::Struct {
            fields: HashMap::new(),
        }))
    }
}