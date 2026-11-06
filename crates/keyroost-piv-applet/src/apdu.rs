use apdu_dispatch::Response as ApduResponse;
use iso7816::Status;

pub type CommandView<'a> = iso7816::command::CommandView<'a>;

#[derive(Debug)]
pub(crate) struct Response(ApduResponse);

impl Response {
    pub(crate) fn into_inner(self) -> ApduResponse {
        self.0
    }

    pub(crate) fn from_slice(data: &[u8]) -> Self {
        let apdu_response = match apdu_dispatch::response::Data::from_slice(data) {
            Ok(data) => ApduResponse::Data(data),
            Err(_) => ApduResponse::Status(Status::NotEnoughMemory),
        };
        Self(apdu_response)
    }

    #[allow(unused)]
    pub(crate) fn data(&self) -> &[u8] {
        match &self.0 {
            ApduResponse::Data(d) => d,
            ApduResponse::Status(_) => &[],
        }
    }

    pub(crate) fn status(&self) -> Status {
        match self.0 {
            ApduResponse::Data(_) => Status::Success,
            ApduResponse::Status(status) => status,
        }
    }
}

impl From<Status> for Response {
    fn from(value: Status) -> Self {
        Self(apdu_dispatch::Response::Status(value))
    }
}

impl From<Vec<u8>> for Response {
    fn from(value: Vec<u8>) -> Self {
        Self::from_slice(&value)
    }
}

impl From<&[u8]> for Response {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl<const N: usize> From<[u8; N]> for Response {
    fn from(value: [u8; N]) -> Self {
        Self::from_slice(&value)
    }
}
