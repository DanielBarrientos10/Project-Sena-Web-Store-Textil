$body = @{
    email = "admin@ddtextil.com"
    password = "admin123"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8081/api/login" -Method POST -ContentType "application/json" -Body $body -ErrorAction Stop
    $response | ConvertTo-Json -Depth 5
} catch {
    Write-Host "Error: $_"
    $_.Exception.Response.StatusCode.Value__
}