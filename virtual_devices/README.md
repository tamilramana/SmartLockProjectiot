# Virtual IoT Devices

This directory contains scripts that simulate the behavior of the ESP8266 physical lock mechanisms. This allows you to test out the logic, workflow, schedules, and frontend device functionality without needing actual arduino hardware hooked up.

The script runs in Node.js and precisely replicates the logic inside `device_secure.ino`, complete with HMAC-SHA256 authentication and signature signing, as well as periodic status and command polling.

## How to Check the Workflow

1. Start your main backend server in a terminal window:
   ```bash
   npm start
   ```

2. Open an entirely separate terminal window (so both programs can run simultaneously), and navigate to this folder:
   ```bash
   cd virtual_devices
   ```

3. Run the virtual device script. By default, it targets the device `front-door`:
   ```bash
   node virtual_device.js
   ```

4. You should see logs indicating successful authentication and the polling loop beginning.
   Now, log in to your web UI (http://localhost:3000), proceed to the `Devices` tab, and attempt to lock/unlock the front door. You will see commands appear in the terminal of the virtual device within 5 seconds as it polls for commands and responds instantly.

### Running Other Devices
You can use environment variables to spawn virtual instances for other devices in your database:
```bash
DEVICE_ID=garage node virtual_device.js
```
