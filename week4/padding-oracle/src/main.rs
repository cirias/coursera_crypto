use actix_http::Error;
use actix_web;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    std::env::set_var("RUST_LOG", "actix_http=trace");
    env_logger::init();

    let ciphertext = hex::decode("f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4").expect("could not decode ciphertext from hex string");
    let mut plaintext = Vec::new();
    plaintext.resize(ciphertext.len() - BLOCK_SIZE, 0);

    let connector = awc::Connector::new().timeout(std::time::Duration::from_secs(30));
    let client = awc::Client::builder()
        .connector(connector)
        .timeout(std::time::Duration::from_secs(30))
        .finish();
    let last = plaintext.len() - 1;

    let b = get_one_plain_byte(&client, last, &ciphertext, &plaintext).await?;
    let pad = b as usize;
    for i in 0..pad {
        plaintext[last - i] = b;
    }

    for i in (0..=(last - pad)).rev() {
        let b = get_one_plain_byte(&client, i, &ciphertext, &plaintext).await?;
        plaintext[i] = b;
    }

    println!(
        "{}",
        std::str::from_utf8(&plaintext[..plaintext.len() - pad]).unwrap()
    );

    Ok(())
}

async fn get_one_plain_byte(
    client: &awc::Client,
    n: usize,
    ciphertext: &[u8],
    plaintext: &[u8],
) -> Result<u8, Error> {
    let guesses = get_guesses(n, &ciphertext, &plaintext);
    let future_results = guesses
        .iter()
        .map(|(guess, code)| verify_guess(&client, *guess, code));
    let results = futures::future::join_all(future_results)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?;
    let filtered: Vec<(u8, bool)> = results
        .into_iter()
        .filter(|(_guess, verified)| *verified)
        .collect();
    assert_eq!(filtered.len(), 1, "must found just one guess");
    Ok(filtered[0].0)
}

async fn verify_guess(client: &awc::Client, guess: u8, code: &[u8]) -> Result<(u8, bool), Error> {
    let verified = verify_code(client, code).await?;
    Ok((guess, verified))
}

async fn verify_code(client: &awc::Client, code: &[u8]) -> Result<bool, Error> {
    let response = client
        .get(format!(
            "http://crypto-class.appspot.com/po?er={}",
            hex::encode(code)
        ))
        .send()
        .await?;
    Ok(response.status() == 404)
}

const BLOCK_SIZE: usize = 16;

fn get_guesses(n: usize, ciphertext: &[u8], plaintext: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let pad_num = (BLOCK_SIZE - n % BLOCK_SIZE) as u8;
    let block_num = n / BLOCK_SIZE; // 2
                                    // block_num
    let mut candidates = Vec::new();
    for guess in 0..=255 {
        let mut code = ciphertext.to_vec();
        code.resize((block_num + 2) * BLOCK_SIZE, 0);
        code[n] ^= guess ^ pad_num;
        for i in n + 1..(block_num + 1) * BLOCK_SIZE {
            code[i] ^= plaintext[i] ^ pad_num;
        }
        candidates.push((guess, code));
    }
    candidates
}
