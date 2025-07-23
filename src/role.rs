use std::{error::Error, str::FromStr};

use serde::{Deserialize, Serialize};

// -- RoleId Structure ---------------------------------------------
/// Represents a unique identifier for a role.
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  PartialOrd,
  Ord,
  Hash,
  Serialize,
  Deserialize,
)]
pub struct RoleId(uuid::Uuid);

// -- Default Implementation for RoleId.
impl Default for RoleId {
  fn default() -> Self {
    Self(uuid::Uuid::nil())
  }
}

// -- Display Implementation for RoleId
impl std::fmt::Display for RoleId {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl RoleId {
  /// Creates a new `RoleId` instance.
  pub fn new() -> Self {
    Self(uuid::Uuid::new_v4())
  }
}

// -- RoleName Structure ---------------------------------------------
/// Represents a name for a role.
#[derive(
  Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct RoleName(std::rc::Rc<str>);

// -- Implements Display for RoleName
impl std::fmt::Display for RoleName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

// -- Implements TryFrom<&str> for RoleName
impl TryFrom<&str> for RoleName {
  type Error = Box<dyn Error>;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    if value.is_empty() {
      Err("Role name cannot be empty".into())
    } else if value.len() < 3 {
      Err("Role name must be at least 3 characters long".into())
    } else {
      Ok(Self(std::rc::Rc::from(value)))
    }
  }
}

impl FromStr for RoleName {
  type Err = Box<dyn Error>;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::try_from(s)
  }
}

// -- Role Structure ---------------------------------------------
/// Represents a user's role.
#[derive(
  Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Role {
  id: RoleId,
  name: RoleName,
}

// -- Implement Role
impl Role {
  pub fn new(name: RoleName) -> Self {
    Self {
      id: RoleId::new(),
      name,
    }
  }

  /// Get the ID of the role.
  ///
  /// # Returns
  ///
  /// The ID of the role.
  pub fn id(&self) -> RoleId {
    self.id
  }

  /// Returns the name of the role.
  ///
  /// # Returns
  ///
  /// The name of the role.
  pub fn name(&self) -> &RoleName {
    &self.name
  }
}
