Simulating a Stuxnet-style PLC rootkit in your Arduino-based CPS lab is feasible safely because you are in a lab and not on industrial hardware. The goal is to mimic the malware’s behavior conceptually: hiding malicious actuator commands while falsifying sensor feedback to SCADA or IDS.

Here’s a structured, step-by-step approach for your lab setup.

1. Understanding the Original Stuxnet Behavior

Stuxnet worked by:

Intercepting legitimate control commands from SCADA/PLC software.

Injecting malicious control commands to centrifuge motors (oscillations, speed changes).

Falsifying sensor readings so SCADA dashboards reported normal operation.

Triggering attacks intermittently to avoid detection.

Your lab can replicate this at a conceptual and functional level.

2. Rootkit Simulation Architecture in Your Lab
SCADA / Node-RED
        │
        │ Modbus / Serial
        ▼
PLC Rootkit Module (Arduino Mega or Python Interceptor)
        │
        │ Malicious commands
        ▼
Actuators (Pump, Valve, Flow Motor)
        │
        │ Falsified sensor readings
        ▼
SCADA receives “normal” data

Key idea: the IDS sees “normal” readings while the physical process behaves maliciously.

3. Implementing a Rootkit Layer

There are two ways to implement the rootkit:

Option A – Internal (Arduino-based)

Modify your PLC firmware to include a hidden mode:

bool rootkitActive = false;
unsigned long lastAttack = 0;

void rootkitBehavior(){

    // Activate periodically
    if(millis() - lastAttack > 10000){ // every 10 sec

        rootkitActive = true;
        lastAttack = millis();

        // malicious oscillation
        pumpState = true;
        valvePosition = 150;
        updateOutputs();

        delay(2000);

        pumpState = false;
        valvePosition = 30;
        updateOutputs();

        // Continue hiding sensor
        fakeTankLevel = map(tankLevel,0,1023,0,100); // normal reading
    }

    if(rootkitActive){
        // overwrite sensor telemetry
        tankLevelToSend = fakeTankLevel;
    }
}

Integrate rootkitBehavior() inside your PLC scan loop.

The SCADA sees normal tank levels, but pump/valve physically oscillates.

Option B – External Interceptor (Python-based)

Place a Python proxy between SCADA and PLC:

SCADA → Modbus Proxy → PLC

Proxy modifies commands and responses:

def intercept_modbus_request(request):
    if rootkit_active:
        # Change command to malicious actuator state
        if request.function_code == WRITE_COIL:
            if request.address == PUMP_COIL:
                # override pump state
                request.value = malicious_value

def intercept_modbus_response(response):
    if rootkit_active:
        # return fake sensor data
        response.registers[TANK_LEVEL] = normal_value

The physical process is affected, SCADA and IDS see “normal” values.

4. Oscillation Attack Example

Simulate Stuxnet-style intermittent actuator manipulation:

Pump: ON → OFF → ON in 2-second intervals.

Valve: partially open → partially closed.

Only active every N seconds to avoid detection.

Sensor telemetry always reports the last safe reading.

5. Hiding the Rootkit

In your lab:

Keep rootkit logic separate from standard PLC logic.

Use internal flags that are invisible in normal HMI or serial outputs.

Optional: hide it in a Python proxy so SCADA sees no firmware modification.

6. Testing IDS Detection

Your IDS should be able to detect:

Type	How
Process anomaly	tank level rising while pump OFF
Oscillation	valve opening/closing unexpectedly
Timing anomaly	control commands sent faster than normal PLC cycle
Physical inconsistency	pump OFF but flow observed
7. Safe Lab Notes

Never connect this to a real industrial PLC or process.

Only use the Arduino + water/fan/servo testbed.

Keep attack frequency and duration limited to avoid physical damage.

8. Summary

Your lab now simulates:

Rootkit behavior: intercepts and modifies actuator commands.

False telemetry: sends normal readings to SCADA.

Intermittent manipulation: mimics real Stuxnet stealthy attacks.

Testable IDS rules: physics-based anomaly detection can detect attacks.
