use crate::core::Address;
use crate::util;
use failure::_core::iter::once;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

pub fn hash(typed_data: Value) -> Result<[u8; 32], failure::Error> {
    let sanitized_data = sanitize(typed_data)?;

    let mut data = Vec::new();
    data.extend_from_slice(&[0x19, 0x01]);

    let domain_hash = hash_struct(
        "EIP712Domain",
        &sanitized_data.domain,
        &sanitized_data.types,
    )?;
    data.extend_from_slice(&domain_hash);

    if sanitized_data.primary_type != "EIP712Domain" {
        let msg_hash = hash_struct(
            &sanitized_data.primary_type,
            &sanitized_data.message,
            &sanitized_data.types,
        )?;
        data.extend_from_slice(&msg_hash);
    }

    let hash = util::keccak256(&data);

    Ok(hash)
}

fn hash_struct(
    primary_type: &str,
    message: &Value,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
) -> Result<[u8; 32], failure::Error> {
    Ok(util::keccak256(&encode_data(primary_type, message, types)?))
}

fn encode_data(
    primary_type: &str,
    message: &Value,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
) -> Result<Vec<u8>, failure::Error> {
    use ethabi::token::Token;

    let mut tokens = vec![Token::FixedBytes(hash_type(primary_type, types)?.to_vec())];

    let data = message
        .as_object()
        .ok_or_else(|| failure::err_msg("encode_data(message) argument should be a JSON object"))?;

    for field in &types[primary_type] {
        let field_data = data.get(&field.name);
        let token = encode_field(&field.name, &field.kind, field_data, types)?;
        tokens.push(token);
    }

    let encoded = ethabi::encode(&tokens);

    Ok(encoded)
}

fn encode_field(
    name: &str,
    kind: &str,
    value: Option<&Value>,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
) -> Result<ethabi::Token, failure::Error> {
    use ethabi::Token;

    if types.contains_key(kind) {
        let token = match value {
            None | Some(Value::Null) => Token::FixedBytes(vec![0_u8; 32]),
            Some(data) => {
                let hash = util::keccak256(&encode_data(kind, data, types)?);
                Token::FixedBytes(hash.to_vec())
            }
        };
        return Ok(token);
    }

    let value = value
        .ok_or_else(|| failure::format_err!("missing value for field {} of type {}", name, kind))?;

    if kind.starts_with("bytes") {
        let value = value.as_str().ok_or_else(|| {
            failure::err_msg("value of type 'bytes*' must be a hex-encoded string")
        })?;
        let value = hex::decode(value)?;
        let hash = util::keccak256(&value);
        let token = Token::FixedBytes(hash.to_vec());
        return Ok(token);
    }

    if kind == "string" {
        let value = value
            .as_str()
            .ok_or_else(|| failure::err_msg("value of type 'string' must be a string"))?;
        let hash = util::keccak256(value.as_bytes());
        let token = Token::FixedBytes(hash.to_vec());
        return Ok(token);
    }

    if kind.ends_with(']') {
        // This is safe since data is expected to be ASCII-only
        let r_index = kind.chars().rev().position(|c| c == '[').unwrap_or(0);
        let index = kind.len() - 1 - r_index;
        let parsed_type = &kind[..index];

        // Ensure value is an array
        let value = value
            .as_array()
            .ok_or_else(|| failure::format_err!("value of type '{}' must be an array", kind))?;

        let tokens = value
            .iter()
            .map(|item| encode_field(name, parsed_type, Some(item), types))
            .collect::<Result<Vec<ethabi::Token>, failure::Error>>()?;

        let encoded = ethabi::encode(&tokens);
        let hash = util::keccak256(&encoded);
        let token = Token::FixedBytes(hash.to_vec());
        return Ok(token);
    }

    match kind {
        "bool" => {
            let value = value.as_bool().ok_or_else(|| {
                failure::err_msg("value of type 'bool' must be either true or false")
            })?;
            Ok(Token::Bool(value))
        }
        "address" => {
            let value = value.as_str().ok_or_else(|| {
                failure::err_msg("value of type 'address' must be a hex-encoded string")
            })?;
            let address = Address::from_str(value)?;
            Ok(Token::Address(address.0.into()))
        }
        "int" | "int8" | "int16" | "int32" | "int64" | "int128" | "int256" => {
            let string_repr = match value {
                Value::String(s) => s.to_string(),
                Value::Number(n) => format!("{}", n),
                _other => {
                    return Err(failure::err_msg(
                        "value of type 'int' must be a hex-encoded string or a number",
                    ))
                }
            };

            let value = U256::from_str(&string_repr).map_err(|e| {
                failure::format_err!("failed to deserialize a value of 'int' type: {:?}", e)
            })?;

            Ok(Token::Int(value))
        }
        "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uint128" | "uint256" => {
            let string_repr = match value {
                Value::String(s) => s.to_string(),
                Value::Number(n) => format!("{}", n),
                _other => {
                    return Err(failure::err_msg(
                        "value of type 'uint' must be a hex-encoded string or a number",
                    ))
                }
            };

            let value = U256::from_str(&string_repr).map_err(|e| {
                failure::format_err!("failed to deserialize a value of 'uint' type: {:?}", e)
            })?;

            Ok(Token::Uint(value))
        }
        other => Err(failure::format_err!("unknown type {}", other)),
    }
}

fn hash_type(
    primary_type: &str,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
) -> Result<[u8; 32], failure::Error> {
    Ok(util::keccak256(
        &encode_type(primary_type, types)?.into_bytes(),
    ))
}

fn encode_type(
    primary_type: &str,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
) -> Result<String, failure::Error> {
    let mut result = String::new();

    let mut deps = find_type_dependencies(primary_type, types, Vec::new());
    deps.sort();

    let deps = deps
        .iter()
        .filter(|&dep| dep != primary_type)
        .map(String::as_str);

    let deps = once(primary_type).chain(deps);

    for t in deps {
        if !types.contains_key(t) {
            return Err(failure::format_err!("No type definition specified: {}", t));
        }

        let children = &types[t];

        result.push_str(t);
        result.push_str("(");
        result.push_str(
            &children
                .iter()
                .map(|child| format!("{} {}", child.kind, child.name))
                .collect::<Vec<_>>()
                .join(","),
        );
        result.push_str(")");
    }

    Ok(result)
}

lazy_static::lazy_static! {
    static ref TYPE_NAME_MATCHER: regex::Regex = regex::Regex::new("^\\w*").unwrap();
}

fn find_type_dependencies(
    primary_type: &str,
    types: &HashMap<TypeName, Vec<SanitizedType>>,
    mut results: Vec<String>,
) -> Vec<String> {
    let primary_type = match TYPE_NAME_MATCHER.find_iter(primary_type).nth(0) {
        Some(x) => x.as_str(),
        None => return results,
    };

    if results.iter().any(|x| x == primary_type) || !types.contains_key(primary_type) {
        return results;
    }

    results.push(primary_type.into());

    for field in &types[primary_type] {
        for dep in find_type_dependencies(&field.kind, types, results.clone()) {
            if results.iter().all(|x| x != &dep) {
                results.push(dep);
            }
        }
    }

    results
}

type TypeName = String;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SanitizedType {
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Clone)]
struct SanitizedData {
    types: HashMap<TypeName, Vec<SanitizedType>>,
    domain: Value,
    primary_type: String,
    message: Value,
}

fn sanitize(typed_data: Value) -> Result<SanitizedData, failure::Error> {
    log::trace!("sanitizing data: {:#?}", typed_data);
    let data = typed_data
        .as_object()
        .ok_or_else(|| failure::err_msg("TypedData parameter must be a JSON Object"))?;

    let primary_type = data
        .get("primaryType")
        .ok_or_else(|| failure::err_msg("primaryType must not present in the TypedData object"))?;
    let primary_type: String = serde_json::from_value(primary_type.clone())
        .map_err(|err| failure::format_err!("failed to deserialize primaryType: {}", err))?;

    let domain = data
        .get("domain")
        .ok_or_else(|| failure::err_msg("domain must be present in the TypedData object"))?;
    let domain = domain.clone();

    let message = data
        .get("message")
        .ok_or_else(|| failure::err_msg("message must be present in the TypedData object"))?;
    let message = message.clone();

    let types = data
        .get("types")
        .ok_or_else(|| failure::err_msg("types must be present in the TypedData object"))?;
    let types: HashMap<TypeName, Vec<SanitizedType>> = serde_json::from_value(types.clone())
        .map_err(|err| failure::format_err!("failed to deserialize types: {}", err))?;

    let data = SanitizedData {
        types,
        domain,
        primary_type,
        message,
    };

    log::trace!("sanitized data: {:#?}", data);

    Ok(data)
}

#[cfg(test)]
mod tests {
    use crate::util::typed::{encode_type, find_type_dependencies, SanitizedData};
    use bitcoin::util::misc::hex_bytes;
    use std::collections::HashMap;

    mod hash {
        use crate::util::typed::hash;

        fn do_test_hash(typed_data: &str, expected: &str) {
            let input =
                serde_json::from_str(typed_data).expect("failed to deserialize 'typed_data' json");
            let got = hash(input).unwrap();
            let got_base64 = base64::encode(&got);
            assert_eq!(got_base64, expected);
        }

        #[test]
        fn test_1() {
            do_test_hash ( r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"# , r#"vmCa7jQ/s8Syjh355jL8pk/Prt4g8C6GJE793zCVe9I="# , ) ;
        }
        #[test]
        fn test_2() {
            do_test_hash ( r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]},"domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"primaryType":"Mail","message":{"from":{"name":"Cow","wallets":["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826","0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"]},"to":[{"name":"Bob","wallets":["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57","0xB0B0b0b0b0b0B000000000000000000000000000"]}],"contents":"Hello, Bob!"}}"# , r#"qFwuKxGGmOiNtoqBBbeUqMx87AdOie+ZHLT19TOBnMI="# , ) ;
        }
        #[test]
        fn test_3() {
            do_test_hash ( r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]},"domain":{"name":"Family Tree","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"primaryType":"Person","message":{"name":"Jon","mother":{"name":"Lyanna","father":{"name":"Rickard"}},"father":{"name":"Rhaegar","father":{"name":"Aeris II"}}}}"# , r#"gHdzufqph51JcbQ4VsTWDC2hXG+MBivZ0zr++3Vt4Zw="# , ) ;
        }
    }

    mod encode_data {
        use crate::util::typed::encode_data;

        fn do_test_encode_data(
            primary_type: &str,
            types_json: &str,
            data_json: &str,
            expected: &str,
        ) {
            let types =
                serde_json::from_str(types_json).expect("failed to deserialize 'types' json");
            let data = serde_json::from_str(data_json).expect("failed to deserialize 'data' json");
            let got = encode_data(primary_type, &data, &types).unwrap();
            let got_base64 = base64::encode(&got);
            assert_eq!(got_base64, expected);
        }

        #[test]
        fn test_1() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"}"# , r#"udjHis+bmHMR3mx7RbtqnI4b82H6f9NGeiFj+ZTHlQCMHSvVNIOUdhcZ2hHsZ+7a6VAtE36JQP7o7Nb2Qe4WSAAAAAAAAAAAAAAAAM0qPZ+TjhPNlH7AWrx/5zTfjdgm"# , ) ;
        }

        #[test]
        fn test_2() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"}"# , r#"udjHis+bmHMR3mx7RbtqnI4b82H6f9NGeiFj+ZTHlQAoysMYqGyKCmqRVsLbosjCNjZ3ugUU72FlktgVV+Z5tgAAAAAAAAAAAAAAALu7u7u7u7u7u7u7u7u7u7u7u7u7"# , ) ;
        }
        #[test]
        fn test_3() {
            do_test_encode_data ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}"# , r#"oM7estwoC6ObhXVG109VScOh173C3Za/iB92EI4j2sL8ceX6J/9Ww1CqUxvBKevfYTt3K2YEZk9djb4huF6wyM1U8HSkrzG0QR/2pgyXGdvVWcIhyKw0ktnYcrBB1wPRtarfMVSiYavdkIb8Ynth78omrlcCcB0FzSMF98UqL8g="# , ) ;
        }
        #[test]
        fn test_4() {
            do_test_encode_data ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"}"# , r#"i3PDxpu4/j1RLsxM91nMeSOfexebD/rKqaddUis5QA/HDvBmOFNbSIH6/KyCh+IQ43af8ajpHxuV1iRuYeTTxsie/apUwPIMet9hKILfCVD1qVFjfgMHzctMZy8pi4vGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAADMzMzMzMzMzMzMzMzMzMzMzMzMzA=="# , ) ;
        }
        #[test]
        fn test_5() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"{"name":"Cow","wallets":["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826","0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"]}"# , r#"+r/h7ZljSfxgJ3CYAr4Z0EfaGqXWiU/19khtktsuaGCMHSvVNIOUdhcZ2hHsZ+7a6VAtE36JQP7o7Nb2Qe4WSIqL/mQrn8GcJa2l2t/TdIdGHcgd1LB3jyYsFj7YG14q"# , ) ;
        }
        #[test]
        fn test_6() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"{"name":"Bob","wallets":["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57","0xB0B0b0b0b0b0B000000000000000000000000000"]}"# , r#"+r/h7ZljSfxgJ3CYAr4Z0EfaGqXWiU/19khtktsuaGAoysMYqGyKCmqRVsLbosjCNjZ3ugUU72FlktgVV+Z5ttJzT0yGzDvZyr8Ewwl1idMWXZXkZI/HLZQ+0WH2Uext"# , ) ;
        }
        #[test]
        fn test_7() {
            do_test_encode_data ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"{"from":{"name":"Cow","wallets":["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826","0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"]},"to":[{"name":"Bob","wallets":["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57","0xB0B0b0b0b0b0B000000000000000000000000000"]}],"contents":"Hello, Bob!"}"# , r#"S9ipork0J7sYSsqB4kvrMP+jx0fioz1CJewIvxLi51ObSEbdSLhm8KxU1hubIannRvkhzvpO6UxMChxJx3T2f8oyK+7IW+JON00Y1YKm8pl/dcVOeZOrW8B0BM4XbKfNtarfMVSiYavdkIb8Ynth78omrlcCcB0FzSMF98UqL8g="# , ) ;
        }
        #[test]
        fn test_8() {
            do_test_encode_data ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"}"# , r#"i3PDxpu4/j1RLsxM91nMeSOfexebD/rKqaddUis5QA/HDvBmOFNbSIH6/KyCh+IQ43af8ajpHxuV1iRuYeTTxsie/apUwPIMet9hKILfCVD1qVFjfgMHzctMZy8pi4vGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAADMzMzMzMzMzMzMzMzMzMzMzMzMzA=="# , ) ;
        }
        #[test]
        fn test_9() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Rickard"}"# , r#"fFyOkMuSyNpTuJOySWJRO+mK/PG1ewAyeuTMFOOmQRZ3PAhyc+MdUmB8TrHShWRUByGJ9i+lGZLVyle+ggfthAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="# , ) ;
        }
        #[test]
        fn test_10() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Lyanna","father":{"name":"Rickard"}}"# , r#"fFyOkMuSyNpTuJOySWJRO+mK/PG1ewAyeuTMFOOmQRav5BQqKz57BQO0SVHmAw4OLFAA74PGGFfi5gA+eu+FcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiPFL4N1GqOxgjMv/bTkjqLTpXN/JZI8NttkqmaJkyzY="# , ) ;
        }
        #[test]
        fn test_11() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Aeris II"}"# , r#"fFyOkMuSyNpTuJOySWJRO+mK/PG1ewAyeuTMFOOmQRYgUg4CR0XbaZQHMeMvMwJq+mluBbGpxYbwNcH8NMO5tQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="# , ) ;
        }
        #[test]
        fn test_12() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Rhaegar","father":{"name":"Aeris II"}}"# , r#"fFyOkMuSyNpTuJOySWJRO+mK/PG1ewAyeuTMFOOmQRayp8f6unaRgeV4o5GmpoEaPoQIDGo3cKC/ioVt+nnTMwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsx0YPLJ/xB5BM/2cexv7le6Pdfez5mf6f4Fbz/U1W4="# , ) ;
        }
        #[test]
        fn test_13() {
            do_test_encode_data ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Jon","mother":{"name":"Lyanna","father":{"name":"Rickard"}},"father":{"name":"Rhaegar","father":{"name":"Aeris II"}}}"# , r#"fFyOkMuSyNpTuJOySWJRO+mK/PG1ewAyeuTMFOOmQRbo1Vqpi2tBHwTbz5sj8pJHuw4zWmvFNoIgAy/cueWSf568+/lPNJ3lC8seOqTx6ziCRFfJmRT+/aJ9z5+Z9heLuFLlq/7/kWowy5QMTiTEPPta6w+oMYvbEN0u0VyMcNg="# , ) ;
        }
        #[test]
        fn test_14() {
            do_test_encode_data ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"{"name":"Family Tree","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"}"# , r#"i3PDxpu4/j1RLsxM91nMeSOfexebD/rKqaddUis5QA8St77MCmZlLC0t0wyLceb7vUW7GXKO9A5So/X3hrD8Jsie/apUwPIMet9hKILfCVD1qVFjfgMHzctMZy8pi4vGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAADMzMzMzMzMzMzMzMzMzMzMzMzMzA=="# , ) ;
        }
    }

    mod encode_type {
        fn do_test_encode_type(primary_type: &str, types_json: &str, expected: &str) {
            let types =
                serde_json::from_str(types_json).expect("failed to deserialize 'types' json");
            let got = super::encode_type(primary_type, &types).unwrap();
            assert_eq!(got, expected);
        }

        #[test]
        fn test_1() {
            do_test_encode_type ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"# , ) ;
        }
        #[test]
        fn test_2() {
            do_test_encode_type ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"Mail(Person from,Person to,string contents)Person(string name,address wallet)"# , ) ;
        }
        #[test]
        fn test_3() {
            do_test_encode_type ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"Person(string name,address wallet)"# , ) ;
        }
        #[test]
        fn test_4() {
            do_test_encode_type ( r#"Group"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"Group(string name,Person[] members)Person(string name,address[] wallets)"# , ) ;
        }
        #[test]
        fn test_5() {
            do_test_encode_type ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"Person(string name,address[] wallets)"# , ) ;
        }
        #[test]
        fn test_6() {
            do_test_encode_type ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"Mail(Person from,Person[] to,string contents)Person(string name,address[] wallets)"# , ) ;
        }
        #[test]
        fn test_7() {
            do_test_encode_type ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"# , ) ;
        }
        #[test]
        fn test_8() {
            do_test_encode_type ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"Person(string name,Person mother,Person father)"# , ) ;
        }
        #[test]
        fn test_9() {
            do_test_encode_type ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"# , ) ;
        }
    }

    mod find_type_deps {
        fn do_test_find_type_dependencies(
            primary_type: &str,
            types_json: &str,
            initial_results: &str,
            expected: &str,
        ) {
            let types =
                serde_json::from_str(types_json).expect("failed to deserialize 'types' json");
            let initial = serde_json::from_str(initial_results)
                .expect("failed to deserialize 'initial results' json");
            let expected: Vec<String> =
                serde_json::from_str(expected).expect("failed to deserialize 'expected' json");
            let got = super::find_type_dependencies(primary_type, &types, initial);
            assert_eq!(got, expected);
        }
        #[test]
        fn test_1() {
            do_test_find_type_dependencies ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"[]"# , r#"["EIP712Domain"]"# , ) ;
        }
        #[test]
        fn test_2() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"["Mail"]"# , r#"["Mail","Person"]"# , ) ;
        }
        #[test]
        fn test_3() {
            do_test_find_type_dependencies ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"[]"# , r#"["Mail","Person"]"# , ) ;
        }
        #[test]
        fn test_4() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]}"# , r#"[]"# , r#"["Person"]"# , ) ;
        }
        #[test]
        fn test_5() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"["Group"]"# , r#"["Group","Person"]"# , ) ;
        }
        #[test]
        fn test_6() {
            do_test_find_type_dependencies ( r#"Group"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"[]"# , r#"["Group","Person"]"# , ) ;
        }
        #[test]
        fn test_7() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"[]"# , r#"["Person"]"# , ) ;
        }
        #[test]
        fn test_8() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"["Mail"]"# , r#"["Mail","Person"]"# , ) ;
        }
        #[test]
        fn test_9() {
            do_test_find_type_dependencies ( r#"Mail"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"[]"# , r#"["Mail","Person"]"# , ) ;
        }
        #[test]
        fn test_10() {
            do_test_find_type_dependencies ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallets","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}],"Group":[{"name":"name","type":"string"},{"name":"members","type":"Person[]"}]}"# , r#"[]"# , r#"["EIP712Domain"]"# , ) ;
        }
        #[test]
        fn test_11() {
            do_test_find_type_dependencies ( r#"Person"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"[]"# , r#"["Person"]"# , ) ;
        }
        #[test]
        fn test_12() {
            do_test_find_type_dependencies ( r#"EIP712Domain"# , r#"{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"mother","type":"Person"},{"name":"father","type":"Person"}]}"# , r#"[]"# , r#"["EIP712Domain"]"# , ) ;
        }
    }
}
