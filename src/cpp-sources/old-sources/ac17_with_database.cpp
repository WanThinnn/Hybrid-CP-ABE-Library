#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <map>
#include <sstream>
#include <algorithm>
#include "rabe/rabe.h"

using namespace std;

// =============================================================================
// DATABASE ATTRIBUTE NORMALIZATION SYSTEM
// =============================================================================

struct UserRecord {
    int id;
    string name;
    int age;
    int salary;
    string department;
    string role;
    int experience_years;
    string security_level;
    bool is_active;
    string location;
};

class AttributeNormalizer {
private:
    // Cac range da dinh nghia truoc cho tung loai du lieu
    map<string, vector<pair<int, int>>> predefined_ranges = {
        {"age", {{18, 25}, {26, 35}, {36, 45}, {46, 60}}},
        {"salary", {{0, 30000}, {30001, 50000}, {50001, 80000}, {80001, 150000}, {150001, 999999}}},
        {"experience", {{0, 2}, {3, 5}, {6, 10}, {11, 20}, {21, 99}}}
    };
    
    map<string, vector<string>> predefined_categories = {
        {"department", {"IT", "HR", "Finance", "Marketing", "Operations"}},
        {"role", {"Manager", "Senior", "Junior", "Lead", "Director"}},
        {"security_level", {"Public", "Internal", "Confidential", "Secret"}},
        {"location", {"HCM", "HaNoi", "DaNang", "CanTho"}}
    };

public:
    // Ham chinh: chuyen UserRecord thanh danh sach attributes cho CP-ABE
    vector<string> normalizeUserToAttributes(const UserRecord& user) {
        vector<string> attributes;
        
        // 1. Normalize so tuoi
        string age_attr = normalizeAge(user.age);
        if (!age_attr.empty()) attributes.push_back(age_attr);
        
        // 2. Normalize luong
        string salary_attr = normalizeSalary(user.salary);
        if (!salary_attr.empty()) attributes.push_back(salary_attr);
        
        // 3. Normalize kinh nghiem
        string exp_attr = normalizeExperience(user.experience_years);
        if (!exp_attr.empty()) attributes.push_back(exp_attr);
        
        // 4. Normalize department
        if (isValidCategory("department", user.department)) {
            attributes.push_back("dept_" + user.department);
        }
        
        // 5. Normalize role
        if (isValidCategory("role", user.role)) {
            attributes.push_back("role_" + user.role);
        }
        
        // 6. Normalize security level
        if (isValidCategory("security_level", user.security_level)) {
            attributes.push_back("security_" + user.security_level);
        }
        
        // 7. Normalize location
        if (isValidCategory("location", user.location)) {
            attributes.push_back("location_" + user.location);
        }
        
        // 8. Normalize boolean
        if (user.is_active) {
            attributes.push_back("status_active");
        } else {
            attributes.push_back("status_inactive");
        }
        
        // 9. Them ID cu the (neu can)
        attributes.push_back("user_id_" + to_string(user.id));
        
        return attributes;
    }
    
    // Ham tao policy tu dieu kien SQL-like
    string createPolicyFromConditions(const string& sql_like_condition) {
        // Vi du: "age >= 26 AND age <= 35 AND department = 'IT' AND salary > 50000"
        // Chuyen thanh: "(age_range_26_35 AND dept_IT) AND salary_range_high"
        
        string policy = sql_like_condition;
        
        // Replace age conditions
        policy = replaceCondition(policy, "age >= 26 AND age <= 35", "age_range_26_35");
        policy = replaceCondition(policy, "age >= 18 AND age <= 25", "age_range_18_25");
        policy = replaceCondition(policy, "age >= 36 AND age <= 45", "age_range_36_45");
        policy = replaceCondition(policy, "age >= 46 AND age <= 60", "age_range_46_60");
        
        // Replace salary conditions
        policy = replaceCondition(policy, "salary > 50000", "salary_range_high");
        policy = replaceCondition(policy, "salary <= 50000", "salary_range_low");
        policy = replaceCondition(policy, "salary > 80000", "salary_range_premium");
        
        // Replace department conditions
        policy = replaceCondition(policy, "department = 'IT'", "dept_IT");
        policy = replaceCondition(policy, "department = 'HR'", "dept_HR");
        policy = replaceCondition(policy, "department = 'Finance'", "dept_Finance");
        
        // Replace role conditions
        policy = replaceCondition(policy, "role = 'Manager'", "role_Manager");
        policy = replaceCondition(policy, "role = 'Senior'", "role_Senior");
        
        return policy;
    }
    
    void printNormalizationRules() {
        cout << "\n=== QUY TAC CHUAN HOA THUOC TINH ===" << endl;
        
        cout << "\n1. TUOI (Age):" << endl;
        for (auto& range : predefined_ranges["age"]) {
            cout << "   " << range.first << "-" << range.second << " -> age_range_" 
                 << range.first << "_" << range.second << endl;
        }
        
        cout << "\n2. LUONG (Salary):" << endl;
        for (auto& range : predefined_ranges["salary"]) {
            cout << "   " << range.first << "-" << range.second << " -> salary_range_" 
                 << getSalaryRangeName(range.first, range.second) << endl;
        }
        
        cout << "\n3. KINH NGHIEM (Experience):" << endl;
        for (auto& range : predefined_ranges["experience"]) {
            cout << "   " << range.first << "-" << range.second << " -> exp_range_" 
                 << range.first << "_" << range.second << endl;
        }
        
        cout << "\n4. CAC THUOC TINH PHAN LOAI:" << endl;
        for (auto& cat : predefined_categories) {
            cout << "   " << cat.first << ": ";
            for (auto& val : cat.second) {
                cout << cat.first << "_" << val << " ";
            }
            cout << endl;
        }
    }

private:
    string normalizeAge(int age) {
        for (auto& range : predefined_ranges["age"]) {
            if (age >= range.first && age <= range.second) {
                return "age_range_" + to_string(range.first) + "_" + to_string(range.second);
            }
        }
        return ""; // Invalid age
    }
    
    string normalizeSalary(int salary) {
        for (auto& range : predefined_ranges["salary"]) {
            if (salary >= range.first && salary <= range.second) {
                return "salary_range_" + getSalaryRangeName(range.first, range.second);
            }
        }
        return "";
    }
    
    string normalizeExperience(int exp) {
        for (auto& range : predefined_ranges["experience"]) {
            if (exp >= range.first && exp <= range.second) {
                return "exp_range_" + to_string(range.first) + "_" + to_string(range.second);
            }
        }
        return "";
    }
    
    string getSalaryRangeName(int min, int max) {
        if (max <= 30000) return "entry";
        if (max <= 50000) return "junior";
        if (max <= 80000) return "mid";
        if (max <= 150000) return "senior";
        return "executive";
    }
    
    bool isValidCategory(const string& category, const string& value) {
        auto it = predefined_categories.find(category);
        if (it == predefined_categories.end()) return false;
        
        return find(it->second.begin(), it->second.end(), value) != it->second.end();
    }
    
    string replaceCondition(string text, const string& from, const string& to) {
        size_t pos = text.find(from);
        if (pos != string::npos) {
            text.replace(pos, from.length(), "\"" + to + "\"");
        }
        return text;
    }
};

// =============================================================================
// CP-ABE IMPLEMENTATION (giu nguyen nhu cu)
// =============================================================================

class AC17CPABE {
private:
    Ac17SetupResult keys;
    bool initialized = false;

public:
    bool setup() {
        cout << "Dang khoi tao he thong CP-ABE AC17..." << endl;
        keys = rabe_ac17_init();
        
        if (keys.master_key == nullptr || keys.public_key == nullptr) {
            cout << "Loi: Khong the khoi tao he thong!" << endl;
            return false;
        }
        
        initialized = true;
        cout << "Khoi tao thanh cong!" << endl;
        return true;
    }
    
    void* genkey(const vector<string>& attributes) {
        if (!initialized) {
            cout << "Loi: He thong chua duoc khoi tao!" << endl;
            return nullptr;
        }
        
        cout << "Dang tao secret key voi attributes: ";
        for (const auto& attr : attributes) {
            cout << attr << " ";
        }
        cout << endl;
        
        vector<const char*> attrs_cstr;
        for (const auto& attr : attributes) {
            attrs_cstr.push_back(attr.c_str());
        }
        
        const void* secret_key = rabe_cp_ac17_generate_secret_key(
            keys.master_key, 
            attrs_cstr.data(), 
            attrs_cstr.size()
        );
        
        if (!secret_key) {
            cout << "Loi: Khong the tao secret key!" << endl;
            const char* error = rabe_get_thread_last_error();
            if (error) {
                cout << "Chi tiet loi: " << error << endl;
            }
            return nullptr;
        }
        
        cout << "Tao secret key thanh cong!" << endl;
        return const_cast<void*>(secret_key);
    }
    
    void* encrypt(const string& policy, const string& plaintext) {
        if (!initialized) {
            cout << "Loi: He thong chua duoc khoi tao!" << endl;
            return nullptr;
        }
        
        cout << "Dang ma hoa voi policy: " << policy << endl;
        cout << "Du lieu goc: " << plaintext << endl;
        
        const void* ciphertext = rabe_cp_ac17_encrypt(
            keys.public_key,
            policy.c_str(),
            plaintext.c_str(),
            plaintext.length()
        );
        
        if (!ciphertext) {
            cout << "Loi: Khong the ma hoa!" << endl;
            const char* error = rabe_get_thread_last_error();
            if (error) {
                cout << "Chi tiet loi: " << error << endl;
            }
            return nullptr;
        }
        
        cout << "Ma hoa thanh cong!" << endl;
        return const_cast<void*>(ciphertext);
    }
    
    string decrypt(void* ciphertext, void* secret_key) {
        if (!initialized) {
            cout << "Loi: He thong chua duoc khoi tao!" << endl;
            return "";
        }
        
        cout << "Dang giai ma..." << endl;
        
        CBoxedBuffer result = rabe_cp_ac17_decrypt(
            static_cast<const void*>(ciphertext),
            static_cast<const void*>(secret_key)
        );
        
        if (result.buffer == nullptr || result.len == 0) {
            cout << "Loi: Khong the giai ma!" << endl;
            const char* error = rabe_get_thread_last_error();
            if (error) {
                cout << "Chi tiet loi: " << error << endl;
            }
            return "";
        }
        
        string decrypted(reinterpret_cast<const char*>(result.buffer), result.len);
        rabe_free_boxed_buffer(result);
        
        cout << "Giai ma thanh cong!" << endl;
        return decrypted;
    }
    
    void cleanup(void* secret_key = nullptr, void* ciphertext = nullptr) {
        if (secret_key) {
            rabe_cp_ac17_free_secret_key(static_cast<const void*>(secret_key));
        }
        if (ciphertext) {
            rabe_cp_ac17_free_cipher(static_cast<const void*>(ciphertext));
        }
        if (initialized) {
            rabe_ac17_free_master_key(keys.master_key);
            rabe_ac17_free_public_key(keys.public_key);
        }
    }
};

// =============================================================================
// DEMO DATABASE NORMALIZATION
// =============================================================================

void demonstrateDatabaseNormalization() {
    cout << "\n=== DEMO CHUAN HOA CO SO DU LIEU CHO CP-ABE ===" << endl;
    
    AttributeNormalizer normalizer;
    AC17CPABE abe;
    
    // Setup ABE system
    if (!abe.setup()) {
        return;
    }
    
    // Tao du lieu mau tu CSDL
    vector<UserRecord> users = {
        {1, "Nguyen Van A", 28, 60000, "IT", "Senior", 5, "Confidential", true, "HCM"},
        {2, "Tran Thi B", 35, 85000, "Finance", "Manager", 8, "Secret", true, "HaNoi"},
        {3, "Le Van C", 22, 25000, "IT", "Junior", 1, "Internal", true, "HCM"},
        {4, "Pham Thi D", 45, 120000, "HR", "Director", 15, "Secret", false, "DaNang"}
    };
    
    normalizer.printNormalizationRules();
    
    cout << "\n=== DU LIEU NGUOI DUNG VA CHUAN HOA ===" << endl;
    
    for (int i = 0; i < users.size(); i++) {
        UserRecord& user = users[i];
        
        cout << "\n" << (i+1) << ". NGUOI DUNG: " << user.name << endl;
        cout << "   Du lieu goc: Age=" << user.age << ", Salary=" << user.salary 
             << ", Dept=" << user.department << ", Role=" << user.role << endl;
        
        // Chuan hoa thanh attributes
        vector<string> attributes = normalizer.normalizeUserToAttributes(user);
        
        cout << "   Attributes da chuan hoa: ";
        for (const auto& attr : attributes) {
            cout << attr << " ";
        }
        cout << endl;
        
        // Test voi policy cu the
        string policy;
        string test_data = "Du lieu bi mat cua " + user.name;
        
        if (i == 0) { // User A - IT Senior
            policy = "(\"age_range_26_35\" and \"dept_IT\") and \"role_Senior\"";
        } else if (i == 1) { // User B - Finance Manager  
            policy = "(\"salary_range_senior\" and \"dept_Finance\") and \"security_Secret\"";
        } else if (i == 2) { // User C - IT Junior
            policy = "(\"age_range_18_25\" and \"dept_IT\") and \"status_active\"";
        } else { // User D - HR Director
            policy = "(\"role_Director\" and \"dept_HR\") and \"exp_range_11_20\"";
        }
        
        cout << "   Policy test: " << policy << endl;
        
        // Tao secret key
        void* secret_key = abe.genkey(attributes);
        if (!secret_key) continue;
        
        // Ma hoa
        void* ciphertext = abe.encrypt(policy, test_data);
        if (!ciphertext) {
            abe.cleanup(secret_key);
            continue;
        }
        
        // Giai ma
        string decrypted = abe.decrypt(ciphertext, secret_key);
        
        if (decrypted == test_data) {
            cout << "   KET QUA: THANH CONG - Nguoi dung co quyen truy cap!" << endl;
        } else {
            cout << "   KET QUA: THAT BAI - Nguoi dung khong co quyen truy cap!" << endl;
        }
        
        abe.cleanup(secret_key, ciphertext);
    }
    
    // Demo SQL-like policy conversion
    cout << "\n=== DEMO CHUYEN DOI POLICY TU SQL-LIKE ===" << endl;
    
    vector<string> sql_conditions = {
        "age >= 26 AND age <= 35 AND department = 'IT'",
        "salary > 50000 AND role = 'Manager'", 
        "department = 'Finance' AND role = 'Senior'"
    };
    
    for (const auto& sql : sql_conditions) {
        cout << "\nSQL goc: " << sql << endl;
        string policy = normalizer.createPolicyFromConditions(sql);
        cout << "CP-ABE Policy: " << policy << endl;
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    
    cout << "Chuong trinh CP-ABE AC17 - Database Integration" << endl;
    cout << "=============================================" << endl;
    
    demonstrateDatabaseNormalization();
    
    cout << "\n=== TAT CA TEST HOAN THANH ===" << endl;
    cout << "\nTONG KET:" << endl;
    cout << "- Da chung minh cach chuan hoa du lieu CSDL thanh attributes CP-ABE" << endl;
    cout << "- He thong co the xu ly du lieu thuc te voi cac range va category" << endl;
    cout << "- Policy co the duoc tao tu dieu kien SQL-like" << endl;
    cout << "- Bao mat duoc dam bao thong qua viec kiem soat thuoc tinh" << endl;
    
    return 0;
}