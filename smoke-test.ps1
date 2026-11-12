# Run in PowerShell 7 while the API is running against a local test database.
param([string]$BaseUrl = 'http://localhost:8080')
$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
$checks = [System.Collections.Generic.List[object]]::new()

function Send($name, $method, $path, $expected, $body = $null, $token = '') {
    $request = @{
        Method = $method
        Uri = "$BaseUrl$path"
        SkipHttpErrorCheck = $true
        TimeoutSec = 10
    }
    if ($null -ne $body) {
        $request.ContentType = 'application/json; charset=utf-8'
        $request.Body = ConvertTo-Json -Compress -InputObject $body
    }
    if ($token) { $request.Headers = @{ Authorization = "Bearer $token" } }
    $response = Invoke-WebRequest @request
    if ($response.StatusCode -ne $expected) {
        throw "$name returned $($response.StatusCode), expected $expected"
    }
    $checks.Add([pscustomobject]@{ Check = $name; HTTP = $response.StatusCode })
    if ($response.Content -and $response.Headers['Content-Type'] -like 'application/json*') {
        return ConvertFrom-Json -InputObject $response.Content -NoEnumerate
    }
}

$api = '/api/v1'
$auth = "$api/auth"
$incidents = "$api/incidents"
$credentials = @{ email = "smoke-$([guid]::NewGuid().ToString('N'))@example.com"; password = 'LocalTest-123!' }
$payload = @{ title = 'Server overheating'; description = 'Core temperature reached 85 C'; priority = 'critical' }

$null = Send 'Swagger UI' GET '/swagger/index.html' 200
$spec = Send 'Swagger specification' GET '/swagger/doc.json' 200
if ($spec.basePath -ne $api -or !$spec.paths.'/incidents'.post.security -or 'BearerAuth' -notin $spec.paths.'/incidents'.post.security[0].PSObject.Properties.Name) {
    throw 'Swagger is missing the API base path or BearerAuth'
}
$user = Send 'Register' POST "$auth/register" 201 $credentials
if (!$user.id -or $user.PSObject.Properties.Name -contains 'password_hash') { throw 'Invalid registration response' }
$null = Send 'Duplicate email' POST "$auth/register" 409 $credentials
$null = Send 'Wrong password' POST "$auth/login" 401 @{ email = $credentials.email; password = 'WrongPassword' }
$login = Send 'Login' POST "$auth/login" 200 $credentials
$token = $login.token
if (!$token) { throw 'Login did not return a token' }

$null = Send 'Public incident list' GET $incidents 200
$null = Send 'Create without token' POST $incidents 401 $payload
$null = Send 'Create with invalid token' POST $incidents 401 $payload 'invalid'
$bad = Send 'Reject invalid priority' POST $incidents 400 @{ title = $payload.title; description = $payload.description; priority = 'urgent' } $token
if (!$bad.fields.priority) { throw 'Missing priority validation detail' }

$incident = Send 'Create incident' POST $incidents 201 $payload $token
if ($incident.user_id -ne $user.id -or $incident.status -ne 'open') { throw 'Invalid owner or initial status' }
$item = "$incidents/$($incident.id)"
$list = Send 'List contains new incident' GET $incidents 200
if ($list.id -notcontains $incident.id) { throw 'Incident missing from list' }
$detail = Send 'Public incident details' GET $item 200
if ($detail.id -ne $incident.id) { throw 'Wrong incident returned' }
$null = Send 'Update without token' PATCH "$item/status" 401 @{ status = 'resolved' }
$null = Send 'Reject invalid status' PATCH "$item/status" 400 @{ status = 'invalid' } $token
$updated = Send 'Update incident status' PATCH "$item/status" 200 @{ status = 'resolved' } $token
if ($updated.status -ne 'resolved' -or (Send 'Read persisted status' GET $item 200).status -ne 'resolved') {
    throw 'Status was not persisted'
}
$null = Send 'Delete without token' DELETE $item 401
$null = Send 'Delete incident' DELETE $item 204 $null $token
$null = Send 'Read deleted incident' GET $item 404
$checks | Format-Table -AutoSize
Write-Host "Passed $($checks.Count) HTTP checks."
