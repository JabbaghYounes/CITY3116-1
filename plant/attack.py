from attack_framework import ICSAttackFramework

attack = ICSAttackFramework()

attack.connect()

print("Select attack")

print("1 - Command Injection")
print("2 - Pump Oscillation")
print("3 - Valve Attack")
print("4 - Replay Attack")
print("5 - Sensor Spoof")
print("6 - Flood Attack")
print("7 - Multi-stage attack")

choice = input("> ")

if choice == "1":
    attack.command_injection()

elif choice == "2":
    attack.pump_oscillation()

elif choice == "3":
    attack.valve_attack()

elif choice == "4":
    attack.replay_attack()

elif choice == "5":
    attack.sensor_spoof()

elif choice == "6":
    attack.modbus_flood()

elif choice == "7":
    attack.multi_stage_attack()
