use esp_idf_svc::sys::person_detection::get_person_score;

use crate::common::config::ConfigType;
use crate::common::registry::ComponentRegistry;
use crate::common::registry::Dependency;
use crate::common::registry::RegistryError;
use crate::common::sensor::GenericReadingsResult;
use crate::common::sensor::Readings;
use crate::common::sensor::Sensor;
use crate::common::sensor::SensorError;
use crate::common::sensor::SensorResult;
use crate::common::sensor::SensorT;
use crate::common::sensor::SensorType;
use crate::common::sensor::TypedReadingsResult;
use crate::common::status::Status;
use crate::common::status::StatusError;
use crate::google::protobuf;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(DoCommand)]
pub struct PersonDetection;

pub fn register_models(registry: &mut ComponentRegistry) -> Result<(), RegistryError> {
    registry.register_sensor("person_detection", &PersonDetection::from_config)?;
    log::debug!("person detection registration ok");
    Ok(())
}

//create a sensor that requires a camera being in the config for creation
impl PersonDetection {
    pub fn from_config(cfg: ConfigType, deps: Vec<Dependency>) -> Result<SensorType, SensorError> {
        //iterate through to find resource type in deps that would be a camera
        //pass reference to lock to camera as something sensor holds so everytime you get reading you lock cam

        log::debug!("person detection sensor instantiated from config");
        Ok(Arc::new(Mutex::new(Self {})))
    }
}

impl Sensor for PersonDetection {}
impl Readings for PersonDetection {
    fn get_generic_readings(&mut self) -> Result<GenericReadingsResult, SensorError> {
        Ok(self
            .get_readings()?
            .into_iter()
            .map(|v| (v.0, SensorResult::<f64> { value: v.1 }.into()))
            .collect())
    }
}

impl SensorT<f64> for PersonDetection {
    fn get_readings(&self) -> Result<TypedReadingsResult<f64>, SensorError> {
        let mut x = -1.0 as f32;
        let ptr = &mut x as *mut f32;
        unsafe{
            if get_person_score(ptr) != true {
                //get_person_score returns a bool and adjusts ptr
                return Err(SensorError::ConfigError("reading error"));
            }
        }
        log::debug!("person_detection - get readings called");
        unsafe{
            let y: f32 = *ptr;
            let ptr_final = y as f64;
            let mut x = HashMap::new();
            x.insert("bytes".to_string(), ptr_final);
            log::debug!("person_detection - get readings OK");
            Ok(x)
        }

    }
}

impl Status for PersonDetection {
    fn get_status(&self) -> Result<Option<protobuf::Struct>, StatusError> {
        log::debug!("Person Detection - get status called");
        Ok(Some(protobuf::Struct {
            fields: HashMap::new(),
        }))
    }
}

// pub fn test() -> f32{
//     let mut value = -1.0;
//     let ptr = &mut value;
//     get_person_score(ptr);
//     return *ptr;
// }
