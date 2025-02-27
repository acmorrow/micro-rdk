// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetEndPositionRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetEndPositionResponse {
    /// Returns 6d pose of the end effector relative to the base, represented by X,Y,Z coordinates which express
    /// millimeters and theta, ox, oy, oz coordinates which express an orientation vector
    #[prost(message, optional, tag="1")]
    pub pose: ::core::option::Option<super::super::super::common::v1::Pose>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JointPositions {
    /// A list of joint positions. Rotations values are in degrees, translational values in mm.
    /// There should be 1 entry in the list per joint DOF, ordered spatially from the base toward the end effector of the arm
    #[prost(double, repeated, tag="1")]
    pub values: ::prost::alloc::vec::Vec<f64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetJointPositionsRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetJointPositionsResponse {
    /// a list JointPositions
    #[prost(message, optional, tag="1")]
    pub positions: ::core::option::Option<JointPositions>,
}
/// Moves an arm to the specified pose that is within the reference frame of the arm.
/// Move request in Motion API has the same behavior except that it performs obstacle avoidance when a world_state
/// message is specified.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveToPositionRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// The destination to move the arm to; this is from the reference frame of the arm.
    #[prost(message, optional, tag="2")]
    pub to: ::core::option::Option<super::super::super::common::v1::Pose>,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveToPositionResponse {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveToJointPositionsRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// A list of joint positions
    /// There should be 1 entry in the list per joint DOF, ordered spatially from the base toward the end effector
    #[prost(message, optional, tag="2")]
    pub positions: ::core::option::Option<JointPositions>,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveToJointPositionsResponse {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveThroughJointPositionsRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// A list of joint positions which will be moved to in the order they are specified
    #[prost(message, repeated, tag="2")]
    pub positions: ::prost::alloc::vec::Vec<JointPositions>,
    /// optional specifications to be obeyed during the motion
    #[prost(message, optional, tag="3")]
    pub options: ::core::option::Option<MoveOptions>,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveThroughJointPositionsResponse {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopRequest {
    /// Name of an arm
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Additional arguments to the method
    #[prost(message, optional, tag="99")]
    pub extra: ::core::option::Option<super::super::super::super::google::protobuf::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopResponse {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Status {
    #[prost(message, optional, tag="1")]
    pub end_position: ::core::option::Option<super::super::super::common::v1::Pose>,
    #[prost(message, optional, tag="2")]
    pub joint_positions: ::core::option::Option<JointPositions>,
    #[prost(bool, tag="3")]
    pub is_moving: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsMovingRequest {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsMovingResponse {
    #[prost(bool, tag="1")]
    pub is_moving: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MoveOptions {
    /// Maximum allowable velocity of an arm joint, in degrees per second
    #[prost(double, optional, tag="1")]
    pub max_vel_degs_per_sec: ::core::option::Option<f64>,
    /// Maximum allowable acceleration of an arm joint, in degrees per second squared
    #[prost(double, optional, tag="2")]
    pub max_acc_degs_per_sec2: ::core::option::Option<f64>,
}
// @@protoc_insertion_point(module)
