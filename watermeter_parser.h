#pragma once

#include <cmath>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace watermeter {

inline std::string trim(const std::string &value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

inline std::string quote(const std::string &value) {
  const char *hex = "0123456789abcdef";
  std::string result = "\"";
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') {
      result += '\\';
      result += c;
    } else if (c < 0x20) {
      result += "\\u00";
      result += hex[c >> 4];
      result += hex[c & 15];
    } else {
      result += c;
    }
  }
  return result + '"';
}

struct Reading {
  std::string name;
  std::vector<std::pair<std::string, std::string>> fields;
  std::vector<std::pair<std::string, std::string>> history;
  std::string get(const std::string &key) const {
    for (const auto &field : fields)
      if (field.first == key)
        return field.second;
    return {};
  }
  bool volume(float &value) const {
    std::string text = get("Vol");
    // Accept decimal comma, but not thousands separators or unknown units.
    for (auto &c : text)
      if (c == ',')
        c = '.';
    char *end = nullptr;
    value = std::strtof(text.c_str(), &end);
    if (end == text.c_str() || !std::isfinite(value) || value < 0)
      return false;
    const std::string unit = trim(end);
    return unit.empty() || unit == "m³" || unit == "m3";
  }
  std::string json(const std::string &uid, const std::string &type, bool full = true) const {
    std::string result = "{";
    auto add = [&result](const std::string &key, const std::string &value) {
      if (result.size() > 1)
        result += ',';
      result += quote(key) + ':' + quote(value);
    };
    if (full) {
      add("Name", name);
      add("NFC_Typ", type);
    }
    add("SN", get("S/N"));
    add("NFC_Id", uid);  // Physical tag UID, not the meter's serial number.
    if (full) {
      for (const auto &field : fields)
        if (field.first != "S/N")
          add(field.first, field.second);
      result += ",\"history\":[";
      for (size_t i = 0; i < history.size(); ++i) {
        if (i)
          result += ',';
        result += "{\"date\":" + quote(history[i].first) + ",\"volume\":" + quote(history[i].second) + '}';
      }
      result += ']';
    } else {
      add("Time", get("Time"));
      add("Vol", get("Vol"));
      result += ",\"HistoryCount\":" + std::to_string(history.size());
    }
    return result + '}';
  }
};

inline bool is_date(const std::string &key) {
  if (key.size() != 10 || key[4] != '-' || key[7] != '-')
    return false;
  for (size_t i = 0; i < key.size(); ++i)
    if (i != 4 && i != 7 && (key[i] < '0' || key[i] > '9'))
      return false;
  return true;
}

inline Reading parse(const std::string &input) {
  Reading reading;
  size_t start = 0;
  while (start < input.size()) {
    const auto end = input.find_first_of("\r\n", start);
    const std::string line = trim(input.substr(start, end == std::string::npos ? end : end - start));
    start = end == std::string::npos ? input.size() : end + 1;
    if (line.empty())
      continue;
    const auto colon = line.find(':');
    const std::string key = trim(line.substr(0, colon));
    if (key == "CRC" || line.compare(0, 4, "CRC=") == 0)
      break;  // CRC is metadata; no claim is made to validate its algorithm.
    if (colon == std::string::npos) {
      if (reading.name.empty())
        reading.name = line;
      continue;
    }
    const std::string value = trim(line.substr(colon + 1));
    if (is_date(key))
      reading.history.emplace_back(key, value);
    else if (!key.empty())
      reading.fields.emplace_back(key, value);
  }
  return reading;
}

}  // namespace watermeter
