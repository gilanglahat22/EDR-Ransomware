#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <mutex>
#include <thread>
#include <chrono>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <memory>
#include <atomic>

// Forward declarations
class FeatureExtractor;
class MLModel;
class FileMonitor;
class APIHook;
class StaticAnalyzer;
class DynamicAnalyzer;

/**
 * @brief RWArmor main class for ransomware detection
 * This class implements a static-informed dynamic analysis approach 
 * for early detection of cryptographic Windows ransomware
 */
class RWArmor {
public:
    RWArmor();
    ~RWArmor();

    // Initialize the detection system
    bool initialize();
    
    // Start monitoring the system
    bool startMonitoring();
    
    // Stop monitoring
    void stopMonitoring();
    
    // Check if a file or process is potentially ransomware
    bool isRansomware(const std::string& file_path);
    
    // Alert when ransomware is detected
    void alert(const std::string& threat_info);
    
    // Set the detection threshold (0.0 to 1.0)
    void setDetectionThreshold(float threshold);

private:
    // Components
    std::unique_ptr<StaticAnalyzer> static_analyzer_;
    std::unique_ptr<DynamicAnalyzer> dynamic_analyzer_;
    std::unique_ptr<FileMonitor> file_monitor_;
    std::unique_ptr<MLModel> ml_model_;
    
    // Detection threshold (0.0 to 1.0)
    float detection_threshold_;
    
    // Flag to indicate if monitoring is active
    std::atomic<bool> is_monitoring_;
    
    // Background monitoring thread
    std::thread monitor_thread_;
    
    // Monitoring thread function
    void monitoringThread();
    
    // Mutex for thread safety
    std::mutex mutex_;
    
    // List of suspicious activities observed
    std::vector<std::string> suspicious_activities_;
    
    // Set of known ransomware file hashes
    std::set<std::string> known_ransomware_hashes_;
    
    // Load known ransomware signatures
    bool loadSignatures(const std::string& signature_file);
};

/**
 * @brief Static analyzer component for examining file properties
 */
class StaticAnalyzer {
public:
    StaticAnalyzer();
    ~StaticAnalyzer();
    
    // Initialize the static analyzer
    bool initialize();
    
    // Analyze a file statically and extract features
    std::vector<float> analyzeFile(const std::string& file_path);
    
    // Check if a file has characteristics of ransomware
    float getRansomwareProbability(const std::string& file_path);
    
    // Get the hash of a file
    std::string getFileHash(const std::string& file_path);

private:
    // Feature extractor for PE files
    std::unique_ptr<FeatureExtractor> feature_extractor_;
    
    // Extract features from import table
    std::vector<float> extractImportFeatures(const std::string& file_path);
    
    // Extract features from the PE header
    std::vector<float> extractHeaderFeatures(const std::string& file_path);
    
    // Extract string features
    std::vector<float> extractStringFeatures(const std::string& file_path);
    
    // Extract entropy features
    std::vector<float> extractEntropyFeatures(const std::string& file_path);
};

/**
 * @brief Dynamic analyzer component for monitoring runtime behavior
 */
class DynamicAnalyzer {
public:
    DynamicAnalyzer();
    ~DynamicAnalyzer();
    
    // Initialize the dynamic analyzer
    bool initialize();
    
    // Start monitoring a specific process
    bool monitorProcess(uint32_t process_id);
    
    // Stop monitoring a specific process
    void stopMonitoringProcess(uint32_t process_id);
    
    // Get the current set of features for a process
    std::vector<float> getCurrentFeatures(uint32_t process_id);
    
    // Check if a process exhibits ransomware behavior
    float getRansomwareProbability(uint32_t process_id);

private:
    // API hooking mechanism
    std::unique_ptr<APIHook> api_hook_;
    
    // Map of process IDs to feature vectors
    std::unordered_map<uint32_t, std::vector<float>> process_features_;
    
    // Map of process IDs to monitoring status
    std::unordered_map<uint32_t, bool> monitored_processes_;
    
    // Mutex for thread safety
    std::mutex mutex_;
    
    // Thread for analyzing behavior
    std::thread analysis_thread_;
    
    // Flag to indicate if the analyzer is running
    std::atomic<bool> is_running_;
    
    // Analyze behavior periodically
    void analysisBehaviorThread();
    
    // Extract file operation features
    std::vector<float> extractFileOpFeatures(uint32_t process_id);
    
    // Extract registry operation features
    std::vector<float> extractRegistryOpFeatures(uint32_t process_id);
    
    // Extract network operation features
    std::vector<float> extractNetworkOpFeatures(uint32_t process_id);
    
    // Extract cryptographic API usage features
    std::vector<float> extractCryptoAPIFeatures(uint32_t process_id);
};

/**
 * @brief File monitoring component for tracking file system changes
 */
class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();
    
    // Initialize the file monitor
    bool initialize();
    
    // Start monitoring the file system
    bool startMonitoring();
    
    // Stop monitoring the file system
    void stopMonitoring();
    
    // Get the latest suspicious file operations
    std::vector<std::string> getSuspiciousOperations();

private:
    // Flag to indicate if monitoring is active
    std::atomic<bool> is_monitoring_;
    
    // Thread for file system monitoring
    std::thread monitor_thread_;
    
    // Mutex for thread safety
    std::mutex mutex_;
    
    // List of suspicious file operations
    std::vector<std::string> suspicious_operations_;
    
    // Monitor file system operations
    void monitorFileSystem();
    
    // Check if a file operation is suspicious
    bool isSuspiciousOperation(const std::string& operation);
};

/**
 * @brief Machine learning model for ransomware detection
 */
class MLModel {
public:
    MLModel();
    ~MLModel();
    
    // Initialize the model
    bool initialize();
    
    // Load model from file
    bool loadModel(const std::string& model_file);
    
    // Save model to file
    bool saveModel(const std::string& model_file);
    
    // Train the model with labeled data
    bool train(const std::vector<std::vector<float>>& features, 
               const std::vector<int>& labels);
    
    // Predict if a feature vector represents ransomware
    float predict(const std::vector<float>& features);

private:
    // The actual ML model implementation
    void* model_impl_;
    
    // Number of features
    int num_features_;
    
    // Flag to indicate if the model is trained
    bool is_trained_;
};

/**
 * @brief API hook mechanism for monitoring system calls
 */
class APIHook {
public:
    APIHook();
    ~APIHook();
    
    // Initialize the API hook
    bool initialize();
    
    // Hook a specific API function
    bool hookAPI(const std::string& module_name, const std::string& function_name);
    
    // Unhook a previously hooked API function
    bool unhookAPI(const std::string& module_name, const std::string& function_name);
    
    // Get recorded API calls for a process
    std::vector<std::string> getAPICalls(uint32_t process_id);
    
    // Clear recorded API calls for a process
    void clearAPICalls(uint32_t process_id);

private:
    // Map of process IDs to lists of API calls
    std::unordered_map<uint32_t, std::vector<std::string>> api_calls_;
    
    // Mutex for thread safety
    std::mutex mutex_;
    
    // Map of hooked functions to original function pointers
    std::unordered_map<std::string, void*> original_functions_;
    
    // Generic API hook callback function
    static void apiHookCallback(uint32_t process_id, const std::string& api_name, 
                               const std::string& params);
};

/**
 * @brief Feature extractor for file analysis
 */
class FeatureExtractor {
public:
    FeatureExtractor();
    ~FeatureExtractor();
    
    // Initialize the feature extractor
    bool initialize();
    
    // Extract features from a file
    std::vector<float> extractFeatures(const std::string& file_path);
    
    // Extract specific feature types
    std::vector<float> extractImportFeatures(const std::string& file_path);
    std::vector<float> extractHeaderFeatures(const std::string& file_path);
    std::vector<float> extractStringFeatures(const std::string& file_path);
    std::vector<float> extractEntropyFeatures(const std::string& file_path);

private:
    // Feature dictionary
    std::vector<std::string> feature_names_;
    
    // Calculate entropy of data
    float calculateEntropy(const std::vector<uint8_t>& data);
    
    // Read PE file sections
    std::vector<std::vector<uint8_t>> readPESections(const std::string& file_path);
    
    // Read PE file imports
    std::vector<std::string> readPEImports(const std::string& file_path);
    
    // Read strings from a file
    std::vector<std::string> extractStrings(const std::string& file_path);
}; 