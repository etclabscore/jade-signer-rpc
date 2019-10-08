//! # Contract
#[allow(dead_code)]
mod error;

pub use self::error::Error;
use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, Token, Tokenizer};
use ethabi::Function;
use hex;
use serde::Deserialize;
use std::fmt;

/// Contract specification
#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    inner: ethabi::Contract,
}

impl Contract {
    /// Try to convert deserialized vector to Contract ABI.
    ///
    /// # Arguments
    ///
    /// * `DATA` - A byte slice
    ///
    #[allow(dead_code)]
    pub fn try_from(data: &[u8]) -> Result<Self, Error> {
        let inner = ethabi::Contract::load(data)?;
        Ok(Contract { inner })
    }

    /// Returns specification of contract function given the function name.
    #[allow(dead_code)]
    pub fn get_function(&self, name: String) -> Option<Function> {
        self.inner.function(&name).ok().cloned()
    }

    /// Encode ABI function call with input params
    #[allow(dead_code)]
    pub fn serialize_function_call(
        &self,
        name: String,
        params: Vec<Token>,
    ) -> Result<Vec<u8>, Error> {
        let f = self.get_function(name).unwrap();
        f.encode_input(&params).map_err(From::from)
    }

    /// Encode ABI input params to hex string
    pub fn serialize_params(types: &[String], values: Vec<String>) -> Result<String, Error> {
        let types = types
            .iter()
            .map(|s| Reader::read(s))
            .collect::<Result<Vec<ParamType>, _>>()?;

        let params: Vec<_> = types.into_iter().zip(values.into_iter()).collect();

        let tokens = params
            .iter()
            .map(|&(ref param, ref value)| LenientTokenizer::tokenize(param, value))
            .collect::<Result<Vec<_>, _>>()?;

        let result = ethabi::encode(&tokens);

        Ok(hex::encode(result))
    }
}

impl fmt::Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethabi::{Function, Param, ParamType};

    #[test]
    fn should_display_contract_abi() {
        let c = b"[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\
                 \"type\":\"string\"}],\"payable\":false,\"type\":\"function\"}]";
        let contract = Contract::try_from(c).unwrap();
        format!("{}", contract);
    }

    #[test]
    fn should_return_correct_function() {
        let c = b"[{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\
                 \"balanceOf\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":\
                 false,\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"name\",\
                 \"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"type\":\
                 \"function\"}]";
        let function = Function {
            name: "balanceOf".to_owned(),
            inputs: vec![Param {
                name: "".to_owned(),
                kind: ParamType::Address,
            }],
            outputs: vec![Param {
                name: "a".to_owned(),
                kind: ParamType::Uint(256),
            }],
            constant: false,
        };
        let contract = Contract::try_from(c).unwrap();
        let f = contract.get_function("balanceOf".to_string()).unwrap();
        assert_eq!(f.inputs, function.inputs);
    }
}
