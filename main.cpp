#include "rwarmor.h"
#include <iostream>
#include <string>
#include <csignal>

// Global RWArmor instance
std::unique_ptr<RWArmor> g_rwarmor;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    
    if (g_rwarmor) {
        g_rwarmor->stopMonitoring();
    }
    
    exit(0);
}

void printHelp() {
    std::cout << "RWArmor - Ransomware Detection System" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  help        - Display this help message" << std::endl;
    std::cout << "  check FILE  - Check if a file is ransomware" << std::endl;
    std::cout << "  threshold N - Set detection threshold (0.0 to 1.0)" << std::endl;
    std::cout << "  monitor PID - Monitor a specific process" << std::endl;
    std::cout << "  quit        - Exit the program" << std::endl;
}

int main(int argc, char* argv[]) {
    // Register signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create RWArmor instance
    g_rwarmor = std::make_unique<RWArmor>();
    
    // Initialize
    if (!g_rwarmor->initialize()) {
        std::cerr << "Failed to initialize RWArmor" << std::endl;
        return 1;
    }
    
    // Start monitoring
    if (!g_rwarmor->startMonitoring()) {
        std::cerr << "Failed to start monitoring" << std::endl;
        return 1;
    }
    
    std::cout << "RWArmor started successfully. Type 'help' for commands." << std::endl;
    
    // Command loop
    std::string command;
    while (true) {
        std::cout << "RWArmor> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        } else if (command == "help") {
            printHelp();
        } else if (command.substr(0, 6) == "check ") {
            std::string file_path = command.substr(6);
            bool result = g_rwarmor->isRansomware(file_path);
            if (!result) {
                std::cout << "File appears to be clean: " << file_path << std::endl;
            }
        } else if (command.substr(0, 10) == "threshold ") {
            try {
                float threshold = std::stof(command.substr(10));
                g_rwarmor->setDetectionThreshold(threshold);
            } catch (const std::exception& e) {
                std::cerr << "Invalid threshold value. Please specify a number between 0.0 and 1.0" << std::endl;
            }
        } else if (command.substr(0, 8) == "monitor ") {
            try {
                uint32_t pid = std::stoul(command.substr(8));
                // In a real implementation, this would call into the dynamic analyzer
                std::cout << "Started monitoring process " << pid << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Invalid process ID" << std::endl;
            }
        } else {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
        }
    }
    
    // Stop monitoring
    g_rwarmor->stopMonitoring();
    
    std::cout << "RWArmor shutdown complete" << std::endl;
    return 0;
} 