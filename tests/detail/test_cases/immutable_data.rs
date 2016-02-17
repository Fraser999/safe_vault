// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::*;
use rand;
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType, ResponseContent, ResponseMessage};
use xor_name::XorName;

pub fn test() {
    println!("Running ImmutableData test");

    let mut client1 = Client::new();
    let mut client2 = Client::new();

    let data = Data::ImmutableData(ImmutableData::new(ImmutableDataType::Normal, generate_random_vec_u8(1024)));

    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutFailure { .. }, .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    create_account(&mut client1);

    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let data_request = DataRequest::ImmutableData(data.name(), ImmutableDataType::Normal);

    match unwrap_option!(client1.get(data_request.clone()), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    match unwrap_option!(client2.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let data_request = DataRequest::ImmutableData(rand::random::<XorName>(), ImmutableDataType::Normal);

    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetFailure { .. }, .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }
}