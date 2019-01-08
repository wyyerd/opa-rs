#[macro_use] extern crate failure;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate try_future;
extern crate futures;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate tokio;


use reqwest::Url;
use serde::{Serialize, de::DeserializeOwned};
use futures::prelude::*;
use futures::future::{self, Either};

use reqwest::async::Client as HttpClient;
use reqwest::async::{Body, Response};

use std::sync::Arc;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Client {
    client: HttpClient,
    addr: Arc<reqwest::Url>,
}

#[derive(Debug, Clone, Serialize)]
struct Input<T> {
    input: T,
}

#[derive(Debug, Clone, Deserialize)]
struct Output<T> {
    result: T,
}

impl Client {
    pub fn new(address: &str) -> Result<Client> {
        let url = Url::parse(address)?.join("v1/")?;
        Ok(Client {
            client: HttpClient::new(),
            addr: Arc::new(url),
        })
    }

    pub fn query<Q: Query>(&self, input: &Q::Input) -> impl Future<Item=Q::Output, Error=Error> {
        self.query_raw::<Q::Input, Q::Output>(Q::path(), input)
    }

    pub fn query_raw<I: Serialize, O: DeserializeOwned>(&self, route: &str, input: &I) -> impl Future<Item=O, Error=Error> {
        let url: Url = try_future!(self.addr.join("data/").and_then(|url| url.join(route)));
        let req: String = try_future!(serde_json::to_string(&Input { input }));
        self.client.post(url)
            .body(req)
            .send()
            .and_then(|mut resp| resp.json::<Output<O>>())
            .map(|output| output.result)
            .from_err().into()
    }

    pub fn set_policy<P: Into<Body>>(&self, policy: P, policy_path: &str) -> impl Future<Item=(), Error=Error> {
        let url: Url = try_future!(self.addr.join("policies/").and_then(|url| url.join(policy_path)));
        self.client.put(url)
            .body(policy)
            .send()
            .from_err()
            .and_then(|r| Client::handle_err(r))
            .into()
    }

    pub fn set_data<D: Into<Body>>(&self, data: D, data_path: &str) -> impl Future<Item=(), Error=Error> {
        let url: Url = try_future!(self.addr.join("data/").and_then(|url| url.join(data_path)));
        self.client.put(url)
            .body(data)
            .send()
            .from_err()
            .and_then(|r| Client::handle_err(r))
            .into()
    }

    fn handle_err(response: Response) -> impl Future<Item=(), Error=Error> {
        if response.status().is_success() {
            Either::A(future::finished(()))
        } else {
            Either::B(response
                .into_body()
                .concat2()
                .from_err()
                .and_then(|msg| {
                    let msg = String::from_utf8(msg.to_vec())
                        .map_err(|_| Error::Unexpected("Invalid UTF-8 received from OPA Agent"))?;
                    Err(Error::Opa(msg))
                })
            )
        }
    }
}

pub trait Query {
    type Input: Serialize;
    type Output: DeserializeOwned;
    fn path() -> &'static str;
}


#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Serde(serde_json::Error),
    #[fail(display = "{}", _0)]
    Http(reqwest::Error),
    #[fail(display = "{}", _0)]
    Url(reqwest::UrlError),
    #[fail(display = "{}", _0)]
    Io(::std::io::Error),
    #[fail(display = "OPA Error: {}", _0)]
    Opa(String),
    #[fail(display = "Unexpected Error: {}", _0)]
    Unexpected(&'static str),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Http(err)
    }
}

impl From<reqwest::UrlError> for Error {
    fn from(err: reqwest::UrlError) -> Self {
        Error::Url(err)
    }
}

impl From<::std::io::Error> for Error {
    fn from(err: ::std::io::Error) -> Self {
        Error::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[derive(Serialize)]
    struct TestInput {
        user: String
    }

    struct TestQuery;

    impl Query for TestQuery {
        type Input = TestInput;
        type Output = bool;

        fn path() -> &'static str {
            "test_policy/allow"
        }
    }

    #[test]
    fn it_works() {
        let data = include_str!("../test_policy/data.json");
        let policy = include_str!("../test_policy/policy.rego");

        let mut runtime = Runtime::new().unwrap();
        let client = Client::new("http://localhost:8181").unwrap();
        runtime.block_on(client.set_data(data, "test_policy")).unwrap();
        runtime.block_on(client.set_policy(policy, "test_policy")).unwrap();

        let alice_allowed = client.query::<TestQuery>(&TestInput { user: "alice".to_owned() });
        let carol_allowed = client.query::<TestQuery>(&TestInput { user: "carol".to_owned() });

        assert!(runtime.block_on(alice_allowed).unwrap());
        assert!(!runtime.block_on(carol_allowed).unwrap());

        runtime.shutdown_now();
    }
}
