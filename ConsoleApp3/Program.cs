using System;
using System.Collections.Generic;
using System.Management;
using System.Text;
using Microsoft.Win32;
using System.Linq;
using System.Threading;

namespace USBHistoryChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Usb Forensics";
            Console.OutputEncoding = Encoding.UTF8;

            DisplayHeader();

            ShowLoadingAnimation("Analyz Memory", 5);

            ShowLoadingAnimation("Scanning for connected USB devices", 5);
            DisplayCurrentlyConnectedDevices();

            ShowLoadingAnimation("Retrieving USB history", 7);
            DisplayUSBHistory();

            PrintMessage(MessageType.Input, "Press any key to exit...");
            Console.ReadKey();
        }

        enum MessageType
        {
            Success,
            Error,
            Info,
            Input
        }

        static void PrintMessage(MessageType type, string message)
        {
            string prefix;
            ConsoleColor color;

            switch (type)
            {
                case MessageType.Success:
                    prefix = "[+]";
                    color = ConsoleColor.Green;
                    break;
                case MessageType.Error:
                    prefix = "[-]";
                    color = ConsoleColor.Red;
                    break;
                case MessageType.Info:
                    prefix = "[%]";
                    color = ConsoleColor.Cyan;
                    break;
                case MessageType.Input:
                    prefix = "[>]";
                    color = ConsoleColor.Yellow;
                    break;
                default:
                    prefix = "[*]";
                    color = ConsoleColor.White;
                    break;
            }

            Console.ForegroundColor = color;
            Console.Write($"{prefix} ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        static void ShowLoadingAnimation(string message, int duration)
        {
            Console.CursorVisible = false;

            int loadingBarWidth = 40;

            PrintMessage(MessageType.Info, $"{message}...");
            Console.Write("    [");

            for (int i = 0; i < loadingBarWidth; i++)
            {
                Thread.Sleep(duration * 1000 / loadingBarWidth);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("■");
                Console.ResetColor();
            }

            Console.WriteLine("]");
            Console.WriteLine();
            Console.CursorVisible = true;
        }

        static void DisplayHeader()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
______                       _          
|  ___|                     (_)         
| |_ ___  _ __ ___ _ __  ___ _  ___ ___ 
|  _/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
| || (_) | | |  __/ | | \__ \ | (__\__ \
\_| \___/|_|  \___|_| |_|___/_|\___|___/
                                          
");
            Console.ResetColor();
            Console.WriteLine();
        }

        static void DisplayCurrentlyConnectedDevices()
        {
            PrintMessage(MessageType.Success, "CURRENTLY CONNECTED USB DEVICES");
            Console.WriteLine("    " + new string('=', 45));

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                int count = 0;

                foreach (ManagementObject drive in searcher.Get())
                {
                    count++;
                    string model = drive["Model"]?.ToString() ?? "Unknown";
                    string serialNumber = drive["SerialNumber"]?.ToString() ?? "Unknown";
                    string size = FormatSize(Convert.ToUInt64(drive["Size"] ?? 0));

                    PrintMessage(MessageType.Success, $"Device {count}:");
                    PrintMessage(MessageType.Info, $"    Model: {model}");
                    PrintMessage(MessageType.Info, $"    Serial: {serialNumber}");
                    PrintMessage(MessageType.Info, $"    Size: {size}");
                    Console.WriteLine();
                }

                if (count == 0)
                {
                    PrintMessage(MessageType.Error, "No USB storage devices currently connected.");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                PrintMessage(MessageType.Error, $"Error detecting connected devices: {ex.Message}");
                Console.WriteLine();
            }
        }

        static void DisplayUSBHistory()
        {
            PrintMessage(MessageType.Success, "USB DEVICE HISTORY (Including Disconnected)");
            Console.WriteLine("    " + new string('=', 50));

            try
            {
                RegistryKey usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");

                if (usbKey != null)
                {
                    string[] deviceClasses = usbKey.GetSubKeyNames();
                    int count = 0;

                    foreach (string deviceClass in deviceClasses)
                    {
                        RegistryKey deviceClassKey = usbKey.OpenSubKey(deviceClass);
                        if (deviceClassKey != null)
                        {
                            string[] devices = deviceClassKey.GetSubKeyNames();

                            foreach (string device in devices)
                            {
                                count++;
                                RegistryKey deviceKey = deviceClassKey.OpenSubKey(device);

                                string friendlyName = GetDeviceFriendlyName(deviceKey);
                                string lastConnected = GetDeviceLastConnected(deviceKey);

                                PrintMessage(MessageType.Success, $"Device {count}:");
                                PrintMessage(MessageType.Info, $"    Name: {friendlyName}");
                                PrintMessage(MessageType.Info, $"    ID: {device}");
                                PrintMessage(MessageType.Info, $"    Type: {deviceClass.Replace('&', ' ')}");
                                if (!string.IsNullOrEmpty(lastConnected))
                                {
                                    PrintMessage(MessageType.Info, $"    Last Connected: {lastConnected}");
                                }
                                Console.WriteLine();

                                deviceKey.Close();
                            }
                            deviceClassKey.Close();
                        }
                    }

                    if (count == 0)
                    {
                        PrintMessage(MessageType.Error, "No USB device history found in registry.");
                        Console.WriteLine();
                    }

                    usbKey.Close();
                }
                else
                {
                    PrintMessage(MessageType.Error, "Could not access USB registry information.");
                    Console.WriteLine();
                }

                GetDeviceSetupHistory();
            }
            catch (Exception ex)
            {
                PrintMessage(MessageType.Error, $"Error retrieving USB history: {ex.Message}");
                Console.WriteLine();
            }
        }

        static string GetDeviceFriendlyName(RegistryKey deviceKey)
        {
            try
            {
                if (deviceKey != null)
                {
                    object friendlyName = deviceKey.GetValue("FriendlyName");
                    if (friendlyName != null)
                    {
                        return friendlyName.ToString();
                    }

                    RegistryKey propertiesKey = deviceKey.OpenSubKey("Device Parameters");
                    if (propertiesKey != null)
                    {
                        object label = propertiesKey.GetValue("Label");
                        propertiesKey.Close();
                        if (label != null)
                        {
                            return label.ToString();
                        }
                    }
                }

                return "Unknown Device";
            }
            catch
            {
                return "Unknown Device";
            }
        }

        static string GetDeviceLastConnected(RegistryKey deviceKey)
        {
            try
            {
                if (deviceKey != null)
                {
                    RegistryKey parent = deviceKey.OpenSubKey("Properties");
                    if (parent != null)
                    {
                        object lastArrival = parent.GetValue("LastArrivalDate");
                        parent.Close();
                        if (lastArrival != null)
                        {
                            return DateTime.FromFileTime((long)lastArrival).ToString();
                        }
                    }
                }
                return string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        static void GetDeviceSetupHistory()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "root\\CIMV2",
                    "SELECT * FROM Win32_PnPEntity WHERE ClassGuid='{36FC9E60-C465-11CF-8056-444553540000}'"
                );

                PrintMessage(MessageType.Success, "ADDITIONAL USB DEVICE INFORMATION");
                Console.WriteLine("    " + new string('=', 40));

                int count = 0;
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    string caption = queryObj["Caption"]?.ToString();
                    string description = queryObj["Description"]?.ToString();
                    string manufacturer = queryObj["Manufacturer"]?.ToString();
                    string deviceID = queryObj["DeviceID"]?.ToString();

                    if (caption != null && (caption.Contains("USB") ||
                        (description != null && description.Contains("USB"))))
                    {
                        count++;
                        PrintMessage(MessageType.Success, $"Device {count}:");
                        PrintMessage(MessageType.Info, $"    Name: {caption}");
                        if (!string.IsNullOrEmpty(manufacturer))
                            PrintMessage(MessageType.Info, $"    Manufacturer: {manufacturer}");
                        PrintMessage(MessageType.Info, $"    Device ID: {deviceID}");
                        Console.WriteLine();
                    }
                }

                if (count == 0)
                {
                    PrintMessage(MessageType.Error, "No additional USB information found.");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                PrintMessage(MessageType.Error, $"Error retrieving additional USB info: {ex.Message}");
                Console.WriteLine();
            }
        }

        static string FormatSize(ulong bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
            int counter = 0;
            decimal number = (decimal)bytes;

            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }

            return $"{number:n2} {suffixes[counter]}";
        }
    }
}