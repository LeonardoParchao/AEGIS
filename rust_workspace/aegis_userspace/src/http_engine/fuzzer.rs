use std::collections::HashMap;
use rand::Rng;

pub struct PayloadFuzzer {
    mutation_rate: f64,
}

impl PayloadFuzzer {
    pub fn new(mutation_rate: f64) -> Self {
        PayloadFuzzer {
            mutation_rate: mutation_rate.clamp(0.0, 1.0),
        }
    }

    pub fn mutate_payload(&self, original: &str) -> Vec<String> {
        let mut mutations = Vec::new();
        
        // Original payload
        mutations.push(original.to_string());
        
        // OWASP API Top 10 payloads
        mutations.extend(self.generate_owasp_mutations(original));
        
        // Random mutations
        mutations.extend(self.generate_random_mutations(original));
        
        mutations
    }

    fn generate_owasp_mutations(&self, original: &str) -> Vec<String> {
        let mut mutations = Vec::new();
        
        // SQL Injection patterns
        let sqli_payloads = vec![
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
        ];
        
        // XSS patterns
        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ];
        
        // Path traversal patterns
        let path_traversal = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2fetc%2fpasswd",
        ];
        
        // Command injection patterns
        let cmd_injection = vec![
            "; cat /etc/passwd",
            "| whoami",
            "$(whoami)",
            "`whoami`",
        ];
        
        for payload in sqli_payloads.iter().chain(xss_payloads.iter())
            .chain(path_traversal.iter()).chain(cmd_injection.iter()) {
            mutations.push(payload.to_string());
            mutations.push(format!("{}{}", original, payload));
            mutations.push(format!("{}={}", original, payload));
        }
        
        mutations
    }

    fn generate_random_mutations(&self, original: &str) -> Vec<String> {
        let mut mutations = Vec::new();
        let mut rng = rand::thread_rng();
        
        // Random character substitution
        if rng.gen_bool(self.mutation_rate) {
            let mut chars: Vec<char> = original.chars().collect();
            if !chars.is_empty() {
                let idx = rng.gen_range(0..chars.len());
                chars[idx] = if rng.gen_bool(0.5) { 
                    chars[idx].to_ascii_uppercase() 
                } else { 
                    chars[idx].to_ascii_lowercase() 
                };
                mutations.push(chars.into_iter().collect());
            }
        }
        
        // Random duplication
        if rng.gen_bool(self.mutation_rate) && !original.is_empty() {
            let idx = rng.gen_range(0..original.len());
            let char_to_dup = original.chars().nth(idx).unwrap();
            let mut mutated = String::new();
            for (i, c) in original.chars().enumerate() {
                mutated.push(c);
                if i == idx {
                    mutated.push(char_to_dup);
                }
            }
            mutations.push(mutated);
        }
        
        // Random deletion
        if rng.gen_bool(self.mutation_rate) && original.len() > 1 {
            let idx = rng.gen_range(0..original.len());
            let mutated: String = original.chars()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, c)| c)
                .collect();
            mutations.push(mutated);
        }
        
        mutations
    }

    pub fn generate_batch_mutations(&self, payloads: &[String]) -> Vec<String> {
        let mut all_mutations = Vec::new();
        
        for payload in payloads {
            all_mutations.extend(self.mutate_payload(payload));
        }
        
        all_mutations
    }
}

impl Default for PayloadFuzzer {
    fn default() -> Self {
        Self::new(0.3)
    }
}
