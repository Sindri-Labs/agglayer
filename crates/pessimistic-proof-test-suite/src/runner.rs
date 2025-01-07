use bincode::config::Options;
pub use pessimistic_proof::{LocalNetworkState, PessimisticProofOutput};
use sp1_sdk::SP1PublicValues;
pub use sp1_sdk::{ExecutionReport, SP1Proof};
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

use crate::PESSIMISTIC_PROOF_ELF;

pub type Hasher = pessimistic_proof::local_exit_tree::hasher::Keccak256Hasher;
pub type Digest = <Hasher as pessimistic_proof::local_exit_tree::hasher::Hasher>::Digest;
pub type MultiBatchHeader = pessimistic_proof::multi_batch_header::MultiBatchHeader<Hasher>;

pub struct ProofOutput {}

/// A convenient interface to run the pessimistic proof ELF bytecode.
pub struct Runner {
    client: sp1_sdk::ProverClient,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner {
    /// Create a new pessimistic proof client.
    pub fn new() -> Self {
        Self::from_client(sp1_sdk::ProverClient::new())
    }

    /// Create a new pessimistic proof client from a custom generic client.
    pub fn from_client(client: sp1_sdk::ProverClient) -> Self {
        Self { client }
    }

    /// Convert inputs to stdin.
    pub fn prepare_stdin(state: &LocalNetworkState, batch_header: &MultiBatchHeader) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write(state);
        stdin.write(batch_header);
        stdin
    }

    /// Extract outputs from the committed public values.
    pub fn extract_output(public_vals: SP1PublicValues) -> PessimisticProofOutput {
        PessimisticProofOutput::bincode_options()
            .deserialize(public_vals.as_slice())
            .expect("deser")
    }

    /// Execute the ELF with given inputs.
    pub fn execute(
        &self,
        state: &LocalNetworkState,
        batch_header: &MultiBatchHeader,
    ) -> anyhow::Result<(PessimisticProofOutput, ExecutionReport)> {
        let stdin = Self::prepare_stdin(state, batch_header);
        let (public_vals, report) = self.client.execute(PESSIMISTIC_PROOF_ELF, stdin).run()?;

        let output = Self::extract_output(public_vals);

        Ok((output, report))
    }

    pub fn get_vkey(&self) -> SP1VerifyingKey {
        let (_pk, vk) = self.client.setup(PESSIMISTIC_PROOF_ELF);
        vk
    }

    // Make API request to Sindri create proof endpoint
    pub async fn get_sindri_proof(input: SP1Stdin, api_key: &str) -> anyhow::Result<String, anyhow::Error> {
        // Set the header
        let mut heads_json = HeaderMap::new();
        headers_json.insert("Accept", "application/json".parse().unwrap());
        headers_json.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {api_key}").to_string()).unwrap(),
        );

        // Serialize the SP1Stdin input to JSON
        let proof_input = serde_json::to_string(&input).unwrap();
        let mut map = json!({"proof_input": proof_input});
        let response = reqwest::Client::new()
            .post(format!("{0}circuit/{identifier}/create_proof", "https://stage.sindri.app/"))
            .headers(headers_json.clone())
            .json(&map)
            .send()
            .await
            .expect("Failed to send request");
        
            let response_body = response.json::<Value>().await.unwrap();

            let proof_id = response_body["proof_id"].as_str().unwrap();

        // Poll the API until the proof is ready and then return the proof
        for i in 0..600 {
            let response = reqwest::Client::new()
                .get(format!("{0}proof/{proof_id}/detail", "https://stage.sindri.app/"))
                .headers(headers_json)
                .send()
                .await
                .expect("Failed to send request");
            assert_eq!(&response.status().as_u16(), &200u16, "Expected status code 201");

            let data = response.json::<Value>().await.unwrap();
            let status = &data["status"].to_string();
            if ["Ready", "Failed"].iter().any(|&s| status.as_str().contains(s)) {
                return Ok(data);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        anyhow::bail!("Proof generation timed out");
    }


    /// Generate one plonk proof.
    pub fn generate_plonk_proof(
        &self,
        state: &LocalNetworkState,
        batch_header: &MultiBatchHeader,
    ) -> anyhow::Result<(
        SP1ProofWithPublicValues,
        SP1VerifyingKey,
        PessimisticProofOutput,
    )> {
        let stdin = Self::prepare_stdin(state, batch_header);
        //let (pk, vk) = self.client.setup(PESSIMISTIC_PROOF_ELF);

        let api_key = "your_api_key_here";
        // Make the call to Sindri here
        let proof_data = self.get_sindri_proof(stdin, api_key).await;

        let proof: SP1ProofWithPublicValues = serde_json::from_str(&proof_data["proof"]).unwrap();
        let output: PessimisticProofOutput = serde_json::from_str(&proof_data["output"]).unwrap();
        let vk: SP1VerifyingKey = serde_json::from_str(&proof_data["vk"]).unwrap();
        Ok((proof, vk, output))
    }
}
