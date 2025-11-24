//! Data structures for Aadhar offline KYC

use serde::{Deserialize, Serialize};
use chrono::{NaiveDate, Datelike};

/// Complete Aadhar offline KYC data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadharData {
    /// Reference ID (last 4 digits of Aadhar + timestamp)
    pub reference_id: String,

    /// Demographic information
    pub poi: PersonalInfo,

    /// Address information
    pub poa: AddressInfo,

    /// Photograph (base64 encoded)
    pub photo: Option<String>,

    /// Digital signature
    pub signature: Signature,

    /// Hashed mobile number (SHA256)
    pub mobile_hash: Option<String>,

    /// Hashed email (SHA256)
    pub email_hash: Option<String>,
}

/// Personal information (Proof of Identity - POI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalInfo {
    /// Full name
    pub name: String,

    /// Date of birth in DD-MM-YYYY format
    pub dob: String,

    /// Gender: M/F/T
    pub gender: String,

    /// Parsed date of birth
    #[serde(skip)]
    pub dob_parsed: Option<NaiveDate>,
}

/// Address information (Proof of Address - POA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Care of
    pub care_of: Option<String>,

    /// Building/House
    pub house: Option<String>,

    /// Street
    pub street: Option<String>,

    /// Landmark
    pub landmark: Option<String>,

    /// Locality
    pub locality: Option<String>,

    /// Village/Town/City
    pub vtc: Option<String>,

    /// Sub-district
    pub subdist: Option<String>,

    /// District
    pub district: Option<String>,

    /// State
    pub state: Option<String>,

    /// PIN code
    pub pincode: Option<String>,

    /// Post office
    pub post_office: Option<String>,

    /// Country
    pub country: Option<String>,
}

impl AddressInfo {
    /// Get the full address as a formatted string
    pub fn full_address(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref house) = self.house {
            parts.push(house.as_str());
        }
        if let Some(ref street) = self.street {
            parts.push(street.as_str());
        }
        if let Some(ref locality) = self.locality {
            parts.push(locality.as_str());
        }
        if let Some(ref vtc) = self.vtc {
            parts.push(vtc.as_str());
        }
        if let Some(ref district) = self.district {
            parts.push(district.as_str());
        }
        if let Some(ref state) = self.state {
            parts.push(state.as_str());
        }
        if let Some(ref pincode) = self.pincode {
            parts.push(pincode.as_str());
        }

        parts.join(", ")
    }

    /// Get city (VTC - Village/Town/City)
    pub fn city(&self) -> Option<&str> {
        self.vtc.as_deref()
    }
}

/// Digital signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature value (base64 encoded)
    pub value: String,

    /// Signature algorithm (e.g., "SHA256withRSA")
    pub algorithm: Option<String>,

    /// Whether signature has been verified
    #[serde(skip)]
    pub verified: bool,
}

impl PersonalInfo {
    /// Parse the date of birth string into a NaiveDate
    pub fn parse_dob(&mut self) -> Result<NaiveDate, chrono::ParseError> {
        let parsed = NaiveDate::parse_from_str(&self.dob, "%d-%m-%Y")?;
        self.dob_parsed = Some(parsed);
        Ok(parsed)
    }

    /// Convenience method: alias for calculate_age()
    pub fn age(&self) -> Option<u32> {
        self.calculate_age()
    }

    /// Calculate age as of today
    pub fn calculate_age(&self) -> Option<u32> {
        let dob = self.dob_parsed?;
        let today = chrono::Local::now().date_naive();

        let mut age = today.year() - dob.year();

        // Adjust if birthday hasn't occurred yet this year
        if today.month() < dob.month() ||
           (today.month() == dob.month() && today.day() < dob.day()) {
            age -= 1;
        }

        Some(age as u32)
    }

    /// Check if person is above a certain age
    pub fn is_above_age(&self, threshold: u32) -> Option<bool> {
        self.calculate_age().map(|age| age >= threshold)
    }
}

/// Raw XML content before parsing
#[derive(Debug, Clone)]
pub struct RawXmlData {
    /// Complete XML content
    pub xml_content: String,

    /// XML content without signature (for verification)
    pub xml_without_signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dob_valid() {
        let mut poi = PersonalInfo {
            name: "Test".to_string(),
            dob: "01-01-1990".to_string(),
            gender: "M".to_string(),
            dob_parsed: None,
        };

        assert!(poi.parse_dob().is_ok());
        assert!(poi.dob_parsed.is_some());
    }

    #[test]
    fn test_parse_dob_invalid() {
        let mut poi = PersonalInfo {
            name: "Test".to_string(),
            dob: "invalid".to_string(),
            gender: "M".to_string(),
            dob_parsed: None,
        };

        assert!(poi.parse_dob().is_err());
    }

    #[test]
    fn test_age_calculation() {
        let mut poi = PersonalInfo {
            name: "Test".to_string(),
            dob: "01-01-2000".to_string(),
            gender: "M".to_string(),
            dob_parsed: None,
        };

        poi.parse_dob().unwrap();
        let age = poi.age();
        assert!(age.is_some());
        let age_val = age.unwrap();
        assert!(age_val >= 23 && age_val <= 26);
    }

    #[test]
    fn test_calculate_age() {
        let mut poi = PersonalInfo {
            name: "Test".to_string(),
            dob: "01-01-2000".to_string(),
            gender: "M".to_string(),
            dob_parsed: None,
        };

        poi.parse_dob().unwrap();
        let age = poi.calculate_age();
        assert!(age.is_some());
    }

    #[test]
    fn test_is_above_age() {
        let mut poi = PersonalInfo {
            name: "Test".to_string(),
            dob: "01-01-2000".to_string(),
            gender: "M".to_string(),
            dob_parsed: None,
        };

        poi.parse_dob().unwrap();
        assert_eq!(poi.is_above_age(18), Some(true));
        assert_eq!(poi.is_above_age(100), Some(false));
    }

    #[test]
    fn test_address_info() {
        let addr = AddressInfo {
            state: Some("Delhi".to_string()),
            district: Some("New Delhi".to_string()),
            care_of: None,
            house: None,
            street: None,
            landmark: None,
            locality: None,
            vtc: None,
            subdist: None,
            pincode: None,
            post_office: None,
            country: None,
        };

        assert_eq!(addr.state, Some("Delhi".to_string()));
        assert_eq!(addr.district, Some("New Delhi".to_string()));
    }
}
