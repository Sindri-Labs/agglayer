use bincode::config::Options;
pub use pessimistic_proof::{LocalNetworkState, PessimisticProofOutput};
use sp1_sdk::SP1PublicValues;
pub use sp1_sdk::{ExecutionReport, SP1Proof};
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use sp1_sdk::block_on;

use dotenvy::dotenv;
use envy;
use sindri::SindriBuilder;
use std::io::Write;

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

    pub fn save_input_to_json(input: SP1Stdin, path: &str) -> anyhow::Result<()> {
        let input_json = serde_json::to_string(&input).unwrap();
        let mut file = std::fs::File::create(path)?;
        file.write_all(input_json.as_bytes())?;
        Ok(())
    }

    // Generate the proof and obtain the verifying key from Sindri
    // This function is async because it makes a network call to Sindri.
    pub async fn get_sindri_proof_async(input: SP1Stdin) -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey, PessimisticProofOutput)> {
        // Convert the input to JSON file.
        let _ = Self::save_input_to_json(input, "input.json");
        
        // Initialize the Sindri client
        dotenv()?;
        let api_key: String = std::env::var("SINDRI_API_KEY")?;
        // Alternatively, set the API key as an env var
        let api_key: String = envy::from_env::<String>()?;
        let sindri_client = SindriBuilder::new(&api_key)
            // .endpoint("https://stage.sindri.app/") // eliminate this line for demo. Default is prod.
            .build()
            .await;

        // Generate the proof on Sindri
        let circuit_id = "f13b2401-ab6e-43e8-a784-112296d78cb3"; // should make public identifier on prod.
        let proof_id = sindri_client
            .prove_circuit(&circuit_id, "input.json")
            .await?;

        let proof_data = sindri_client
            .get_proof_details(&proof_id)
            .await?;

        let proof: SP1ProofWithPublicValues = serde_json::from_value(proof_data["proof"].clone())?;
        let vk: SP1VerifyingKey = serde_json::from_value(proof_data["vk"].clone())?;
        let output = Self::extract_output(proof.public_values.clone());

        Ok((proof, vk, output))
    }

    // This method is a wrapper around the async method above.
    pub fn get_sindri_proof(input: SP1Stdin) -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey, PessimisticProofOutput)> {
        let (proof, vk, output) = block_on(Self::get_sindri_proof_async(input))?;
        Ok((proof, vk, output))
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
        // Save the input as JSON file
        let stdin = Self::prepare_stdin(state, batch_header);

        // Make the call to Sindri here
        let proof_data = Self::get_sindri_proof(stdin)?; 

        Ok(proof_data)
    }
}
