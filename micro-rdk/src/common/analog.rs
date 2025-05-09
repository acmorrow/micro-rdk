#![allow(dead_code)]

use super::config::{AttributeError, Kind};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalogError {
    #[error("analog read error {0}")]
    AnalogReadError(i32),
}

pub struct FakeAnalogReader {
    name: String,
    value: u16,
}

impl FakeAnalogReader {
    pub fn new(name: String, value: u16) -> Self {
        Self { name, value }
    }
    fn internal_name(&self) -> String {
        self.name.clone()
    }
    fn internal_read(&self) -> Result<u16, AnalogError> {
        Ok(self.value)
    }
}

impl AnalogReader<u16> for FakeAnalogReader {
    type Error = AnalogError;
    fn name(&self) -> String {
        self.internal_name()
    }
    fn read(&mut self) -> Result<u16, Self::Error> {
        self.internal_read()
    }
    fn resolution(&self) -> AnalogResolution {
        Default::default()
    }
}

#[derive(Debug, Default)]
pub struct AnalogResolution {
    pub min_range: f32,
    pub max_range: f32,
    pub step_size: f32,
}

pub trait AnalogReader<Word>: Send {
    type Error;
    fn read(&mut self) -> Result<Word, Self::Error>;
    fn name(&self) -> String;
    /// Returns the resolution information for converting
    /// the raw value of `read` to voltage (units of voltage
    /// is dependent on the implementer)
    fn resolution(&self) -> AnalogResolution;
}

impl<A, Word> AnalogReader<Word> for Arc<Mutex<A>>
where
    A: ?Sized + AnalogReader<Word>,
{
    type Error = A::Error;
    fn read(&mut self) -> Result<Word, Self::Error> {
        self.lock().unwrap().read()
    }
    fn name(&self) -> String {
        self.lock().unwrap().name()
    }
    fn resolution(&self) -> AnalogResolution {
        self.lock().unwrap().resolution()
    }
}

pub(crate) struct AnalogReaderConfig {
    pub(crate) name: String,
    pub(crate) pin: i32,
}

impl TryFrom<&Kind> for AnalogReaderConfig {
    type Error = AttributeError;
    fn try_from(value: &Kind) -> Result<Self, Self::Error> {
        if !value.contains_key("name")? {
            return Err(AttributeError::KeyNotFound("name".to_string()));
        }
        if !value.contains_key("pin")? {
            return Err(AttributeError::KeyNotFound("pin".to_string()));
        }
        let name = value.get("name")?.unwrap().try_into()?;
        let pin: i32 = value.get("pin")?.unwrap().try_into()?;
        Ok(Self { name, pin })
    }
}

pub type AnalogReaderType<W, E = AnalogError> = Arc<Mutex<dyn AnalogReader<W, Error = E>>>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::common::config::{Component, DynamicComponentConfig, Kind, Model, ResourceName};

    use super::AnalogReaderConfig;
    #[test_log::test]
    fn test_analog_reader_config() {
        let robot_config: &[DynamicComponentConfig] = &[DynamicComponentConfig {
            name: ResourceName::new_builtin("board".to_owned(), "board".to_owned()),
            model: Model::new_builtin("fake".to_owned()),
            attributes: Some(HashMap::from([
                (
                    "pins".to_owned(),
                    Kind::VecValue(vec![
                        Kind::StringValue("11".to_owned()),
                        Kind::StringValue("12".to_owned()),
                        Kind::StringValue("13".to_owned()),
                    ]),
                ),
                (
                    "analogs".to_owned(),
                    Kind::VecValue(vec![
                        Kind::StructValue(HashMap::from([
                            ("name".to_owned(), Kind::StringValue("string".to_owned())),
                            ("pin".to_owned(), Kind::StringValue("12".to_owned())),
                        ])),
                        Kind::StructValue(HashMap::from([
                            ("name".to_owned(), Kind::StringValue("string".to_owned())),
                            ("pin".to_owned(), Kind::StringValue("11".to_owned())),
                        ])),
                    ]),
                ),
            ])),
            data_collector_configs: vec![],
        }];

        let val = robot_config[0].get_attribute::<Vec<AnalogReaderConfig>>("analogs");

        assert!(&val.is_ok());

        let val = val.unwrap();

        assert_eq!(val.len() as u32, 2);

        assert_eq!(val[0].name, "string");
        assert_eq!(val[1].name, "string");
        assert_eq!(val[0].pin, 12);
        assert_eq!(val[1].pin, 11);
    }
}
