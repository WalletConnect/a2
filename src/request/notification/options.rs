use crate::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct CollapseId<'a> {
    pub value: &'a str,
}

/// A collapse-id container. Will not allow bigger id's than 64 bytes.
impl<'a> CollapseId<'a> {
    pub fn new(value: &'a str) -> Result<CollapseId<'a>, Error> {
        if value.len() > 64 {
            Err(Error::InvalidOptions(String::from(
                "The collapse-id is too big. Maximum 64 bytes.",
            )))
        } else {
            Ok(CollapseId { value })
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
/// The apns-push-type header field has the following valid values.
/// The descriptions below describe when and how to use these values.
/// Send an apns-push-type header with each push. Recent and upcoming features
/// may not work if this header is missing. See the table above to determine if
/// this header is required or optional.
///
/// see https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns#4294485
pub enum PushType {
    /// The push type for notifications that trigger a user interaction—for example,
    /// an alert, badge, or sound.
    #[default]
    Alert,
    /// The push type for notifications that deliver content in the background, and
    /// don’t trigger any user interactions.
    Background,
    /// The push type for notifications that request a user’s location.
    Location,
    /// The push type for notifications that provide information about an incoming
    /// Voice-over-IP (VoIP) call.
    Voip,
    /// The push type to signal changes to a File Provider extension.
    FileProvider,
    /// The push type for notifications that tell managed devices to contact the
    /// MDM server.
    Mdm,
    ///  The push type to signal changes to a live activity session.
    LiveActivity,
    /// The push type for notifications that provide information about updates to
    /// your application’s push to talk services.
    PushToTalk,
}

impl fmt::Display for PushType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PushType::Alert => "alert",
            PushType::Background => "background",
            PushType::Location => "location",
            PushType::Voip => "voip",
            PushType::FileProvider => "fileprovider",
            PushType::Mdm => "mdm",
            PushType::LiveActivity => "liveactivity",
            PushType::PushToTalk => "pushtotalk",
        })
    }
}

/// Headers to specify options to the notification.
#[derive(Debug, Default, Clone)]
pub struct NotificationOptions<'a> {
    /// A canonical UUID that identifies the notification. If there is an error
    /// sending the notification, APNs uses this value to identify the
    /// notification to your server.
    pub apns_id: Option<&'a str>,

    /// The apns-push-type header field has the following valid values.
    ///
    /// Recent and upcoming features may not work if this header is missing.
    /// See the table above to determine if this header is required or optional.
    pub apns_push_type: Option<PushType>,

    /// A UNIX epoch date expressed in seconds (UTC). This header identifies the
    /// date when the notification is no longer valid and can be discarded.
    ///
    /// If this value is nonzero, APNs stores the notification and tries to
    /// deliver it at least once, repeating the attempt as needed if it is unable
    /// to deliver the notification the first time. If the value is 0, APNs
    /// treats the notification as if it expires immediately and does not store
    /// the notification or attempt to redeliver it.
    pub apns_expiration: Option<u64>,

    /// The priority of the notification. If `None`, the APNs server sets the priority to High.
    pub apns_priority: Option<Priority>,

    /// The topic of the remote notification, which is typically the bundle ID
    /// for your app. The certificate you create in your developer account must
    /// include the capability for this topic.
    ///
    /// If your certificate includes multiple topics, you must specify a value
    /// for this header.
    ///
    /// If you omit this request header and your APNs certificate does not
    /// specify multiple topics, the APNs server uses the certificate’s Subject
    /// as the default topic.
    ///
    /// If you are using a provider token instead of a certificate, you must
    /// specify a value for this request header. The topic you provide should be
    /// provisioned for the your team named in your developer account.
    pub apns_topic: Option<&'a str>,

    /// Multiple notifications with the same collapse identifier are displayed to the
    /// user as a single notification. The value of this key must not exceed 64
    /// bytes.
    pub apns_collapse_id: Option<CollapseId<'a>>,
}

/// The importance how fast to bring the notification for the user..
#[derive(Debug, Clone)]
pub enum Priority {
    /// Send the push message immediately. Notifications with this priority must
    /// trigger an alert, sound, or badge on the target device. Cannot be used
    /// with the silent notification.
    High,

    /// Send the push message at a time that takes into account power
    /// considerations for the device. Notifications with this priority might be
    /// grouped and delivered in bursts. They are throttled, and in some cases
    /// are not delivered.
    Normal,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let priority = match self {
            Priority::High => "10",
            Priority::Normal => "5",
        };

        write!(f, "{}", priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn test_collapse_id_under_64_chars() {
        let collapse_id = CollapseId::new("foo").unwrap();
        assert_eq!("foo", collapse_id.value);
    }

    #[test]
    fn test_collapse_id_over_64_chars() {
        let mut long_string = Vec::with_capacity(65);
        long_string.extend_from_slice(&[65; 65]);

        let collapse_id = CollapseId::new(str::from_utf8(&long_string).unwrap());
        assert!(collapse_id.is_err());
    }
}
