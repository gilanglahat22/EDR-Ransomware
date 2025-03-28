#include "rwarmor.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <ctime>
#include <cstring>
#include <functional>
#include <cctype>

// RWArmor implementation

RWArmor::RWArmor() 
    : detection_threshold_(0.7), 
      is_monitoring_(false) {
    // Create components
    static_analyzer_ = std::make_unique<StaticAnalyzer>();
    dynamic_analyzer_ = std::make_unique<DynamicAnalyzer>();
    file_monitor_ = std::make_unique<FileMonitor>();
    ml_model_ = std::make_unique<MLModel>();
}

RWArmor::~RWArmor() {
    // Make sure monitoring is stopped
    stopMonitoring();
}

bool RWArmor::initialize() {
    // Initialize all components
    if (!static_analyzer_->initialize()) {
        std::cerr << "Failed to initialize static analyzer" << std::endl;
        return false;
    }
    
    if (!dynamic_analyzer_->initialize()) {
        std::cerr << "Failed to initialize dynamic analyzer" << std::endl;
        return false;
    }
    
    if (!file_monitor_->initialize()) {
        std::cerr << "Failed to initialize file monitor" << std::endl;
        return false;
    }
    
    if (!ml_model_->initialize()) {
        std::cerr << "Failed to initialize ML model" << std::endl;
        return false;
    }
    
    // Load known ransomware signatures
    if (!loadSignatures("signatures.txt")) {
        std::cerr << "Warning: Failed to load signatures" << std::endl;
        // Continue anyway, can work without signatures
    }
    
    std::cout << "RWArmor initialized successfully" << std::endl;
    return true;
}

bool RWArmor::startMonitoring() {
    if (is_monitoring_) {
        std::cout << "Monitoring is already active" << std::endl;
        return true;
    }
    
    // Start file monitoring
    if (!file_monitor_->startMonitoring()) {
        std::cerr << "Failed to start file monitoring" << std::endl;
        return false;
    }
    
    // Start monitoring thread
    is_monitoring_ = true;
    monitor_thread_ = std::thread(&RWArmor::monitoringThread, this);
    
    std::cout << "RWArmor monitoring started" << std::endl;
    return true;
}

void RWArmor::stopMonitoring() {
    if (!is_monitoring_) {
        return;
    }
    
    // Stop monitoring
    is_monitoring_ = false;
    
    // Stop file monitoring
    file_monitor_->stopMonitoring();
    
    // Wait for monitoring thread to finish
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    std::cout << "RWArmor monitoring stopped" << std::endl;
}

bool RWArmor::isRansomware(const std::string& file_path) {
    // First check if the file matches known ransomware hashes
    std::string file_hash = static_analyzer_->getFileHash(file_path);
    
    // Check in known signatures
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (known_ransomware_hashes_.find(file_hash) != known_ransomware_hashes_.end()) {
            alert("File matches known ransomware signature: " + file_path);
            return true;
        }
    }
    
    // Perform static analysis
    float static_probability = static_analyzer_->getRansomwareProbability(file_path);
    
    // If static analysis is highly confident, we can return immediately
    if (static_probability > 0.9) {
        alert("High confidence ransomware detection (static): " + file_path);
        return true;
    }
    
    // If we reach this point and static analysis probability is above threshold,
    // we should report as possible ransomware
    if (static_probability >= detection_threshold_) {
        alert("Possible ransomware detected (static): " + file_path);
        return true;
    }
    
    // Otherwise, we need more evidence to make a determination
    return false;
}

void RWArmor::alert(const std::string& threat_info) {
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    
    // Format timestamp
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
    
    // Log the alert
    std::string alert_message = ss.str() + " - ALERT: " + threat_info;
    
    // Output to console and log file
    std::cout << alert_message << std::endl;
    
    // Add to suspicious activities
    {
        std::lock_guard<std::mutex> lock(mutex_);
        suspicious_activities_.push_back(alert_message);
    }
    
    // TODO: Implement more sophisticated alerting (email, SIEM integration, etc.)
}

void RWArmor::setDetectionThreshold(float threshold) {
    if (threshold < 0.0f) threshold = 0.0f;
    if (threshold > 1.0f) threshold = 1.0f;
    
    detection_threshold_ = threshold;
    std::cout << "Detection threshold set to " << threshold << std::endl;
}

void RWArmor::monitoringThread() {
    while (is_monitoring_) {
        // Get suspicious file operations
        auto suspicious_ops = file_monitor_->getSuspiciousOperations();
        
        // Process suspicious operations
        for (const auto& op : suspicious_ops) {
            // Log suspicious activity
            std::lock_guard<std::mutex> lock(mutex_);
            suspicious_activities_.push_back(op);
        }
        
        // Sleep for a bit to avoid using too much CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool RWArmor::loadSignatures(const std::string& signature_file) {
    std::ifstream file(signature_file);
    if (!file.is_open()) {
        std::cerr << "Failed to open signature file: " << signature_file << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Add to known ransomware hashes
        std::lock_guard<std::mutex> lock(mutex_);
        known_ransomware_hashes_.insert(line);
    }
    
    std::cout << "Loaded " << known_ransomware_hashes_.size() << " ransomware signatures" << std::endl;
    return true;
}

// StaticAnalyzer implementation

StaticAnalyzer::StaticAnalyzer() {
    feature_extractor_ = std::make_unique<FeatureExtractor>();
}

StaticAnalyzer::~StaticAnalyzer() {
}

bool StaticAnalyzer::initialize() {
    return feature_extractor_->initialize();
}

std::vector<float> StaticAnalyzer::analyzeFile(const std::string& file_path) {
    std::vector<float> features;
    
    // Extract various feature types
    auto import_features = extractImportFeatures(file_path);
    auto header_features = extractHeaderFeatures(file_path);
    auto string_features = extractStringFeatures(file_path);
    auto entropy_features = extractEntropyFeatures(file_path);
    
    // Combine all features
    features.insert(features.end(), import_features.begin(), import_features.end());
    features.insert(features.end(), header_features.begin(), header_features.end());
    features.insert(features.end(), string_features.begin(), string_features.end());
    features.insert(features.end(), entropy_features.begin(), entropy_features.end());
    
    return features;
}

float StaticAnalyzer::getRansomwareProbability(const std::string& file_path) {
    // Extract features from the file
    auto features = analyzeFile(file_path);
    
    // Mock implementation - in real code, this would use a trained ML model
    // Here we just use a simple heuristic for demonstration
    
    // Check for high entropy (common in encrypted/packed malware)
    float entropy_score = 0.0f;
    if (!features.empty()) {
        entropy_score = features.back();  // Assuming entropy is the last feature
    }
    
    // Simulate a probability score based on entropy
    // (This is just for demonstration - real implementation would use ML model)
    float score = entropy_score / 8.0f;  // Max entropy is 8 bits
    
    return score;
}

std::string StaticAnalyzer::getFileHash(const std::string& file_path) {
    // Simple hash calculation (in real code, you'd use a cryptographic hash like SHA-256)
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return "";
    }
    
    // Calculate simple hash of file
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    // Read the file in chunks to avoid loading large files into memory
    const int BUFFER_SIZE = 8192;
    char buffer[BUFFER_SIZE];
    uint64_t hash = 0;
    
    while (file.read(buffer, BUFFER_SIZE)) {
        for (int i = 0; i < file.gcount(); ++i) {
            hash = hash * 31 + static_cast<unsigned char>(buffer[i]);
        }
    }
    
    // Process any remaining bytes
    for (int i = 0; i < file.gcount(); ++i) {
        hash = hash * 31 + static_cast<unsigned char>(buffer[i]);
    }
    
    ss << std::setw(16) << hash;
    return ss.str();
}

std::vector<float> StaticAnalyzer::extractImportFeatures(const std::string& file_path) {
    return feature_extractor_->extractImportFeatures(file_path);
}

std::vector<float> StaticAnalyzer::extractHeaderFeatures(const std::string& file_path) {
    return feature_extractor_->extractHeaderFeatures(file_path);
}

std::vector<float> StaticAnalyzer::extractStringFeatures(const std::string& file_path) {
    return feature_extractor_->extractStringFeatures(file_path);
}

std::vector<float> StaticAnalyzer::extractEntropyFeatures(const std::string& file_path) {
    return feature_extractor_->extractEntropyFeatures(file_path);
}

// DynamicAnalyzer implementation

DynamicAnalyzer::DynamicAnalyzer() 
    : is_running_(false) {
    api_hook_ = std::make_unique<APIHook>();
}

DynamicAnalyzer::~DynamicAnalyzer() {
    // Make sure the analysis thread is stopped
    is_running_ = false;
    if (analysis_thread_.joinable()) {
        analysis_thread_.join();
    }
}

bool DynamicAnalyzer::initialize() {
    if (!api_hook_->initialize()) {
        std::cerr << "Failed to initialize API hook" << std::endl;
        return false;
    }
    
    // Start analysis thread
    is_running_ = true;
    analysis_thread_ = std::thread(&DynamicAnalyzer::analysisBehaviorThread, this);
    
    return true;
}

bool DynamicAnalyzer::monitorProcess(uint32_t process_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already monitoring
    if (monitored_processes_.find(process_id) != monitored_processes_.end() &&
        monitored_processes_[process_id]) {
        return true;  // Already monitoring
    }
    
    // Set up monitoring
    monitored_processes_[process_id] = true;
    
    // Hook relevant APIs for this process
    // These are critical APIs used by ransomware
    api_hook_->hookAPI("kernel32.dll", "CreateFileW");
    api_hook_->hookAPI("kernel32.dll", "WriteFile");
    api_hook_->hookAPI("kernel32.dll", "ReadFile");
    api_hook_->hookAPI("kernel32.dll", "DeleteFileW");
    api_hook_->hookAPI("kernel32.dll", "MoveFileW");
    api_hook_->hookAPI("kernel32.dll", "SetFileAttributesW");
    api_hook_->hookAPI("advapi32.dll", "CryptEncrypt");
    api_hook_->hookAPI("advapi32.dll", "CryptDecrypt");
    api_hook_->hookAPI("advapi32.dll", "CryptAcquireContextW");
    api_hook_->hookAPI("advapi32.dll", "CryptGenKey");
    api_hook_->hookAPI("advapi32.dll", "RegCreateKeyExW");
    api_hook_->hookAPI("advapi32.dll", "RegSetValueExW");
    api_hook_->hookAPI("advapi32.dll", "RegDeleteKeyW");
    api_hook_->hookAPI("ws2_32.dll", "connect");
    api_hook_->hookAPI("ws2_32.dll", "send");
    api_hook_->hookAPI("ws2_32.dll", "recv");
    
    return true;
}

void DynamicAnalyzer::stopMonitoringProcess(uint32_t process_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    monitored_processes_[process_id] = false;
    
    // Clear stored features
    process_features_.erase(process_id);
    
    // Clear API calls
    api_hook_->clearAPICalls(process_id);
}

std::vector<float> DynamicAnalyzer::getCurrentFeatures(uint32_t process_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Return empty vector if process not found
    if (process_features_.find(process_id) == process_features_.end()) {
        return std::vector<float>();
    }
    
    return process_features_[process_id];
}

float DynamicAnalyzer::getRansomwareProbability(uint32_t process_id) {
    // Get current features for the process
    auto features = getCurrentFeatures(process_id);
    
    // Mock implementation - would use ML model in real code
    
    // If no features are collected yet, return 0
    if (features.empty()) {
        return 0.0f;
    }
    
    // Simple heuristic based on feature count
    // In a real implementation, we would use a proper ML model
    float file_op_intensity = 0.0f;
    float crypto_api_usage = 0.0f;
    
    // Extract components from features vector (placeholder logic)
    if (features.size() >= 2) {
        file_op_intensity = features[0];
        crypto_api_usage = features[1];
    }
    
    // Calculate probability based on file operations and crypto API usage
    float score = 0.5f * file_op_intensity + 0.5f * crypto_api_usage;
    
    // Ensure probability is between 0 and 1
    if (score < 0.0f) score = 0.0f;
    if (score > 1.0f) score = 1.0f;
    
    return score;
}

void DynamicAnalyzer::analysisBehaviorThread() {
    while (is_running_) {
        std::vector<uint32_t> processes_to_analyze;
        
        // Get list of processes to analyze
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& entry : monitored_processes_) {
                if (entry.second) {  // If monitoring is enabled
                    processes_to_analyze.push_back(entry.first);
                }
            }
        }
        
        // Analyze each process
        for (auto process_id : processes_to_analyze) {
            // Extract features
            auto file_op_features = extractFileOpFeatures(process_id);
            auto registry_op_features = extractRegistryOpFeatures(process_id);
            auto network_op_features = extractNetworkOpFeatures(process_id);
            auto crypto_api_features = extractCryptoAPIFeatures(process_id);
            
            // Combine features
            std::vector<float> combined_features;
            combined_features.insert(combined_features.end(), file_op_features.begin(), file_op_features.end());
            combined_features.insert(combined_features.end(), registry_op_features.begin(), registry_op_features.end());
            combined_features.insert(combined_features.end(), network_op_features.begin(), network_op_features.end());
            combined_features.insert(combined_features.end(), crypto_api_features.begin(), crypto_api_features.end());
            
            // Update features
            {
                std::lock_guard<std::mutex> lock(mutex_);
                process_features_[process_id] = combined_features;
            }
        }
        
        // Sleep for a bit to avoid using too much CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

std::vector<float> DynamicAnalyzer::extractFileOpFeatures(uint32_t process_id) {
    // Extract file operation features from API calls
    auto api_calls = api_hook_->getAPICalls(process_id);
    
    // Count file operations of various types
    int create_count = 0;
    int write_count = 0;
    int delete_count = 0;
    int rename_count = 0;
    
    for (const auto& call : api_calls) {
        if (call.find("CreateFile") != std::string::npos) {
            create_count++;
        } else if (call.find("WriteFile") != std::string::npos) {
            write_count++;
        } else if (call.find("DeleteFile") != std::string::npos) {
            delete_count++;
        } else if (call.find("MoveFile") != std::string::npos) {
            rename_count++;
        }
    }
    
    // Normalize counts
    float max_count = 100.0f;  // Threshold for normalization
    float normalized_create = std::min(1.0f, static_cast<float>(create_count) / max_count);
    float normalized_write = std::min(1.0f, static_cast<float>(write_count) / max_count);
    float normalized_delete = std::min(1.0f, static_cast<float>(delete_count) / max_count);
    float normalized_rename = std::min(1.0f, static_cast<float>(rename_count) / max_count);
    
    // Calculate file operation intensity
    // High values of write and delete are suspicious for ransomware
    float file_op_intensity = 0.5f * normalized_write + 0.3f * normalized_delete + 
                             0.1f * normalized_create + 0.1f * normalized_rename;
    
    return {file_op_intensity};
}

std::vector<float> DynamicAnalyzer::extractRegistryOpFeatures(uint32_t process_id) {
    // Extract registry operation features from API calls
    auto api_calls = api_hook_->getAPICalls(process_id);
    
    // Count registry operations
    int reg_create_count = 0;
    int reg_set_count = 0;
    int reg_delete_count = 0;
    
    for (const auto& call : api_calls) {
        if (call.find("RegCreateKey") != std::string::npos) {
            reg_create_count++;
        } else if (call.find("RegSetValue") != std::string::npos) {
            reg_set_count++;
        } else if (call.find("RegDeleteKey") != std::string::npos) {
            reg_delete_count++;
        }
    }
    
    // Normalize counts
    float max_count = 50.0f;  // Threshold for normalization
    float normalized_create = std::min(1.0f, static_cast<float>(reg_create_count) / max_count);
    float normalized_set = std::min(1.0f, static_cast<float>(reg_set_count) / max_count);
    float normalized_delete = std::min(1.0f, static_cast<float>(reg_delete_count) / max_count);
    
    // Calculate registry operation intensity
    float reg_op_intensity = 0.4f * normalized_set + 0.3f * normalized_create + 0.3f * normalized_delete;
    
    return {reg_op_intensity};
}

std::vector<float> DynamicAnalyzer::extractNetworkOpFeatures(uint32_t process_id) {
    // Extract network operation features from API calls
    auto api_calls = api_hook_->getAPICalls(process_id);
    
    // Count network operations
    int connect_count = 0;
    int send_count = 0;
    int recv_count = 0;
    
    for (const auto& call : api_calls) {
        if (call.find("connect") != std::string::npos) {
            connect_count++;
        } else if (call.find("send") != std::string::npos) {
            send_count++;
        } else if (call.find("recv") != std::string::npos) {
            recv_count++;
        }
    }
    
    // Normalize counts
    float max_count = 20.0f;  // Threshold for normalization
    float normalized_connect = std::min(1.0f, static_cast<float>(connect_count) / max_count);
    float normalized_send = std::min(1.0f, static_cast<float>(send_count) / max_count);
    float normalized_recv = std::min(1.0f, static_cast<float>(recv_count) / max_count);
    
    // Calculate network operation intensity
    float net_op_intensity = 0.4f * normalized_connect + 0.3f * normalized_send + 0.3f * normalized_recv;
    
    return {net_op_intensity};
}

std::vector<float> DynamicAnalyzer::extractCryptoAPIFeatures(uint32_t process_id) {
    // Extract cryptographic API features from API calls
    auto api_calls = api_hook_->getAPICalls(process_id);
    
    // Count crypto operations
    int crypt_acquire_count = 0;
    int crypt_encrypt_count = 0;
    int crypt_decrypt_count = 0;
    int crypt_genkey_count = 0;
    
    for (const auto& call : api_calls) {
        if (call.find("CryptAcquireContext") != std::string::npos) {
            crypt_acquire_count++;
        } else if (call.find("CryptEncrypt") != std::string::npos) {
            crypt_encrypt_count++;
        } else if (call.find("CryptDecrypt") != std::string::npos) {
            crypt_decrypt_count++;
        } else if (call.find("CryptGenKey") != std::string::npos) {
            crypt_genkey_count++;
        }
    }
    
    // Normalize counts
    float max_count = 20.0f;  // Threshold for normalization
    float normalized_acquire = std::min(1.0f, static_cast<float>(crypt_acquire_count) / max_count);
    float normalized_encrypt = std::min(1.0f, static_cast<float>(crypt_encrypt_count) / max_count);
    float normalized_decrypt = std::min(1.0f, static_cast<float>(crypt_decrypt_count) / max_count);
    float normalized_genkey = std::min(1.0f, static_cast<float>(crypt_genkey_count) / max_count);
    
    // Calculate crypto API usage intensity
    // High values of encrypt are suspicious for ransomware
    float crypto_api_intensity = 0.5f * normalized_encrypt + 0.2f * normalized_genkey + 
                                0.2f * normalized_acquire + 0.1f * normalized_decrypt;
    
    return {crypto_api_intensity};
} 