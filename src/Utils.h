#pragma once

#include <sstream>
#include <string>
#include <vector>

class Utils
{
public:
  static std::string GetFilePath(std::string strPath, bool bUserPath = true);
  static std::string UrlEncode(const std::string &string);
  static double StringToDouble(const std::string &value);
  static int StringToInt(const std::string &value);
  static std::string b64_encode(unsigned char const* in, unsigned int in_len, bool urlEncode);
};
