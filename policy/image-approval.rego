package main

# Block any image with a CRITICAL severity vulnerability
deny[msg] {
  result := input.Results[_]
  vuln := result.Vulnerabilities[_]
  
  # Trigger on CRITICAL
  vuln.Severity == "CRITICAL"
  
  # Format the message using ONLY fields guaranteed to exist
  msg := sprintf("CRITICAL CVE Detected: %s in package '%s'", [
    vuln.VulnerabilityID, 
    vuln.PkgName
  ])
}
