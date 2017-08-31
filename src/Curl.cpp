#include "Curl.h"
#include "client.h"
#include <kodi/Filesystem.h>

using namespace std;

static const string SET_COOKIE = "Set-Cookie";

string Curl::cookie = "";

Curl::Curl()
{
}

Curl::~Curl()
{
}

string Curl::Post(string url, string postData, int &statusCode)
{
  kodi::vfs::CFile file;
  if (!file.CURLCreate(url))
  {
    statusCode = 500;
    return "";
  }

  if (cookie != "") {
	  file.CURLAddOption(ADDON_CURL_OPTION_HEADER, SET_COOKIE, cookie);
  }

  file.CURLAddOption(ADDON_CURL_OPTION_HEADER, "acceptencoding", "gzip");
  if (postData.size() != 0)
  {
    string base64 = Base64Encode((const unsigned char *) postData.c_str(),
        postData.size(), false);
    file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "postdata", base64.c_str());
  }

  if (!file.CURLOpen(READ_NO_CACHE))
  {
    statusCode = 403;
    return "";
  }

  // read the file
  static const unsigned int CHUNKSIZE = 16384;
  char buf[CHUNKSIZE + 1];
  size_t nbRead;
  string body = "";
  while ((nbRead = file.Read(buf, CHUNKSIZE)) > 0 && ~nbRead)
  {
    buf[nbRead] = 0x0;
    body += buf;
  }

  if (cookie == "") {
	  cookie = file.GetProperty(ADDON_FILE_PROPERTY_RESPONSE_HEADER, SET_COOKIE);
  }


  file.Close();
  statusCode = 200;
  return body;
}

std::string Curl::Base64Encode(unsigned char const* in, unsigned int in_len,
    bool urlEncode)
{
  std::string ret;
  int i(3);
  unsigned char c_3[3];
  unsigned char c_4[4];

  const char *to_base64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  while (in_len)
  {
    i = in_len > 2 ? 3 : in_len;
    in_len -= i;
    c_3[0] = *(in++);
    c_3[1] = i > 1 ? *(in++) : 0;
    c_3[2] = i > 2 ? *(in++) : 0;

    c_4[0] = (c_3[0] & 0xfc) >> 2;
    c_4[1] = ((c_3[0] & 0x03) << 4) + ((c_3[1] & 0xf0) >> 4);
    c_4[2] = ((c_3[1] & 0x0f) << 2) + ((c_3[2] & 0xc0) >> 6);
    c_4[3] = c_3[2] & 0x3f;

    for (int j = 0; (j < i + 1); ++j)
    {
      if (urlEncode && to_base64[c_4[j]] == '+')
        ret += "%2B";
      else if (urlEncode && to_base64[c_4[j]] == '/')
        ret += "%2F";
      else
        ret += to_base64[c_4[j]];
    }
  }
  while ((i++ < 3))
    ret += urlEncode ? "%3D" : "=";
  return ret;
}
