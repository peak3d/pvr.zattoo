#include <iostream>
#include <string>
#include "ZatData.h"
#include <sstream>
#include "tinyxml2/tinyxml2.h"
#include "p8-platform/sockets/tcp.h"
#include <map>
#include <time.h>
#include <random>
#include "Utils.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <stdlib.h>
#endif

#ifdef TARGET_ANDROID
#include "to_string.h"
#endif

#ifdef TARGET_WINDOWS
#define timegm _mkgmtime
#endif

using namespace ADDON;
using namespace std;
using namespace rapidjson;

static const string data_file =
    "special://profile/addon_data/pvr.zattoo/data.json";
static const string zattooServer = "https://zattoo.com";

string ZatData::HttpGet(string url, bool isInit)
{
  return HttpPost(url, "", isInit);
}

string ZatData::HttpPost(string url, string postData, bool isInit)
{
  XBMC->Log(LOG_DEBUG, "Http-Request: %s.", url.c_str());

  void* file = XBMC->CURLCreate(url.c_str());
  if (!file)
    return false;

  if (!postData.empty())
  {
    std::string b64PostData(Utils::b64_encode(reinterpret_cast<const unsigned char *>(postData.c_str()), postData.size(), false));
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "postdata", b64PostData.c_str());
  }

  if (!cookies.empty())
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "cookie", cookies.c_str());

  if (!XBMC->CURLOpen(file, XFILE::READ_CHUNKED | XFILE::READ_NO_CACHE) && !isInit)
  {
    XBMC->Log(LOG_ERROR, "Open URL failed. Try to re-init session.");
    /*if (!InitSession())
    {
      XBMC->Log(LOG_ERROR, "Re-init of session. Failed.");
      return "";
    }
    return curl->Post(url, postData, statusCode);
    */
    return "";
  }

  char *cookiesPtr = XBMC->GetFileProperty(file, XFILE::FILE_PROPERTY_RESPONSE_HEADER, "set-cookie");
  if (cookiesPtr && *cookiesPtr)
  {
    cookies = cookiesPtr;
    std::string::size_type paramPos = cookies.find(';');
    if (paramPos != std::string::npos)
      cookies.resize(paramPos);
  }
  XBMC->FreeString(cookiesPtr);

  std::string content;
  static const unsigned int CHUNKSIZE = 16384;
  char buf[CHUNKSIZE];
  size_t nbRead;
  while ((nbRead = XBMC->ReadFile(file, buf, CHUNKSIZE)) > 0 && ~nbRead)
    content.append(buf, nbRead);

  return content;
}

bool ZatData::ReadDataJson()
{
  void* file;
  char buf[256];
  size_t nbRead;
  string jsonString;
  if (!XBMC->FileExists(data_file.c_str(), true))
  {
    return true;
  }
  file = XBMC->CURLCreate(data_file.c_str());
  if (!file || !XBMC->CURLOpen(file, 0))
  {
    XBMC->Log(LOG_ERROR, "Loading data.json failed.");
    return false;
  }
  while ((nbRead = XBMC->ReadFile(file, buf, 255)) > 0)
  {
    buf[nbRead] = 0;
    jsonString.append(buf);
  }
  XBMC->CloseFile(file);

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError())
  {
    XBMC->Log(LOG_ERROR, "Parsing data.json failed.");
    return false;
  }

  const Value& recordings = doc["recordings"];
  for (Value::ConstValueIterator itr = recordings.Begin();
      itr != recordings.End(); ++itr)
  {
    const Value& recording = (*itr);
    ZatRecordingData *recData = new ZatRecordingData();
    recData->recordingId = recording["recordingId"].GetString();
    recData->playCount = recording["playCount"].GetInt();
    recData->lastPlayedPosition = recording["lastPlayedPosition"].GetInt();
    recData->stillValid = false;
    recordingsData[recData->recordingId] = recData;
  }

  XBMC->Log(LOG_DEBUG, "Loaded data.json.");
  return true;
}

bool ZatData::WriteDataJson()
{
  void* file;
  if (!(file = XBMC->OpenFileForWrite(data_file.c_str(), true)))
  {
    XBMC->Log(LOG_ERROR, "Save data.json failed.");
    return false;
  }

  Document d;
  d.SetObject();

  Value a(kArrayType);
  Document::AllocatorType& allocator = d.GetAllocator();
  for (auto const& item : recordingsData)
  {
    if (!item.second->stillValid)
    {
      continue;
    }

    Value r;
    r.SetObject();
    Value recordingId;
    recordingId.SetString(item.second->recordingId.c_str(),
        item.second->recordingId.length(), allocator);
    r.AddMember("recordingId", recordingId, allocator);
    r.AddMember("playCount", item.second->playCount, allocator);
    r.AddMember("lastPlayedPosition", item.second->lastPlayedPosition,
        allocator);
    a.PushBack(r, allocator);
  }
  d.AddMember("recordings", a, allocator);

  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);
  const char* output = buffer.GetString();
  XBMC->WriteFile(file, output, strlen(output));
  XBMC->CloseFile(file);
  return true;
}

string ZatData::GetUUID()
{
  void* file;
  char buf[37];
  size_t nbRead;

  if (!uuid.empty())
  {
    return uuid;
  }

  uuid = GenerateUUID();
  return uuid;
}

string ZatData::GenerateUUID()
{
  std::random_device rd;
  std::mt19937 rng(rd());
  std::uniform_int_distribution<int> uni(0, 15);
  ostringstream uuid;

  uuid << std::hex;

  for (int i = 0; i < 32; i++)
  {
    if (i == 8 || i == 12 || i == 16 || i == 20)
    {
      uuid << "-";
    }
    if (i == 12)
    {
      uuid << 4;
    } else if (i == 16)
    {
      uuid << ((uni(rng) % 4) + 8);
    } else
    {
      uuid << uni(rng);
    }
  }
  return uuid.str();
}

bool ZatData::LoadAppId()
{
  string html = HttpGet(zattooServer, true);

  appToken = "";
  //There seems to be a problem with old gcc and osx with regex. Do it the dirty way:
  int basePos = html.find("window.appToken = '") + 19;
  if (basePos > 19)
  {
    int endPos = html.find("'", basePos);
    appToken = html.substr(basePos, endPos - basePos);
  }

  if (appToken.empty())
  {
    XBMC->Log(LOG_ERROR, "Error getting app token");
    return false;
  }

  XBMC->Log(LOG_DEBUG, "Loaded App token %s", appToken.c_str());
  return true;

}

bool ZatData::SendHello(string uuid)
{
  XBMC->Log(LOG_DEBUG, "Send hello.");
  ostringstream dataStream;
  dataStream << "uuid=" << uuid << "&lang=en&format=json&client_app_token="
      << appToken;

  string jsonString = HttpPost(zattooServer + "/zapi/session/hello",
      dataStream.str(), true);

  Document doc;
  doc.Parse(jsonString.c_str());
  if (!doc.GetParseError() && doc["success"].GetBool())
  {
    XBMC->Log(LOG_DEBUG, "Hello was successful.");
    return true;
  } else
  {
    XBMC->Log(LOG_ERROR, "Hello failed.");
    return false;
  }
}

bool ZatData::Login()
{
  XBMC->Log(LOG_DEBUG, "Try to login.");

  ostringstream dataStream;
  dataStream << "login=" << Utils::UrlEncode(username) << "&password="
      << Utils::UrlEncode(password) << "&format=json";
  string jsonString = HttpPost(zattooServer + "/zapi/account/login",
      dataStream.str(), true);

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    XBMC->Log(LOG_ERROR, "Login failed.");
    return false;
  }

  XBMC->Log(LOG_DEBUG, "Login was successful.");
  return true;
}

bool ZatData::InitSession()
{
  string jsonString = HttpGet(zattooServer + "/zapi/v2/session", true);
  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    XBMC->Log(LOG_ERROR, "Initialize session failed.");
    return false;
  }

  if (!doc["session"]["loggedin"].GetBool())
  {
    XBMC->Log(LOG_DEBUG, "Need to login.");

    string uuid = GetUUID();
    if (uuid.empty())
    {
      return false;
    }

    SendHello(uuid);
    //Ignore if hello fails

    if (!Login())
    {
      return false;
    }
    jsonString = HttpGet(zattooServer + "/zapi/v2/session", true);
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError() || !doc["success"].GetBool()
        || !doc["session"]["loggedin"].GetBool())
    {
      XBMC->Log(LOG_ERROR, "Initialize session failed.");
      return false;
    }
  }

  const Value& session = doc["session"];

  countryCode = session["aliased_country_code"].GetString();
  recallEnabled = streamType == "dash" && session["recall_eligible"].GetBool();
  recordingEnabled = session["recording_eligible"].GetBool();
  if (recallEnabled)
  {
    maxRecallSeconds = session["recall_seconds"].GetInt();
  }
  if (recordingEnabled && updateThread == NULL)
  {
    updateThread = new UpdateThread();
  }
  powerHash = session["power_guide_hash"].GetString();
  return true;
}

bool ZatData::LoadChannels()
{
  std::map<std::string, ZatChannel> allChannels;
  string jsonString = HttpGet(zattooServer + "/zapi/channels/favorites");
  Document favDoc;
  favDoc.Parse(jsonString.c_str());

  if (favDoc.GetParseError() || !favDoc["success"].GetBool())
  {
    return false;
  }
  const Value& favs = favDoc["favorites"];

  ostringstream urlStream;
  urlStream << zattooServer + "/zapi/v2/cached/channels/" << powerHash
      << "?details=False";
  jsonString = HttpGet(urlStream.str());

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    std::cout << "Failed to parse configuration\n";
    return false;
  }

  int channelNumber = favs.Size();
  const Value& groups = doc["channel_groups"];

  //Load the channel groups and channels
  for (Value::ConstValueIterator itr = groups.Begin(); itr != groups.End();
      ++itr)
  {
    PVRZattooChannelGroup group;
    const Value& groupItem = (*itr);
    group.name = groupItem["name"].GetString();
    const Value& channels = groupItem["channels"];
    for (Value::ConstValueIterator itr1 = channels.Begin();
        itr1 != channels.End(); ++itr1)
    {
      const Value& channelItem = (*itr1);
      const Value& qualities = channelItem["qualities"];
      for (Value::ConstValueIterator itr2 = qualities.Begin();
          itr2 != qualities.End(); ++itr2)
      {
        const Value& qualityItem = (*itr2);
        std::string avail = qualityItem["availability"].GetString();
        if (avail == "available")
        {
          ZatChannel channel;
          channel.name = qualityItem["title"].GetString();
          std::string cid = channelItem["cid"].GetString();
          channel.iUniqueId = GetChannelId(cid.c_str());
          channel.cid = cid;
          channel.iChannelNumber = ++channelNumber;
          channel.strLogoPath = "http://logos.zattic.com";
          channel.strLogoPath.append(qualityItem["logo_white_84"].GetString());
          group.channels.insert(group.channels.end(), channel);
          allChannels[cid] = channel;
          channelsByCid[channel.cid] = channel;
          channelsByUid[channel.iUniqueId] = channel;
          break;
        }
      }
    }
    if (!favoritesOnly && group.channels.size() > 0)
      channelGroups.insert(channelGroups.end(), group);
  }

  PVRZattooChannelGroup favGroup;
  favGroup.name = "Favoriten";

  for (Value::ConstValueIterator itr = favs.Begin(); itr != favs.End(); ++itr)
  {
    const Value& favItem = (*itr);
    string favCid = favItem.GetString();
    if (allChannels.find(favCid) != allChannels.end())
    {
      ZatChannel channel = allChannels[favCid];
      channel.iChannelNumber = favGroup.channels.size() + 1;
      favGroup.channels.insert(favGroup.channels.end(), channel);
      channelsByCid[channel.cid] = channel;
      channelsByUid[channel.iUniqueId] = channel;
    }
  }

  if (favGroup.channels.size() > 0)
    channelGroups.insert(channelGroups.end(), favGroup);

  return true;
}

int ZatData::GetChannelId(const char * strChannelName)
{
  int iId = 0;
  int c;
  while (c = *strChannelName++)
    iId = ((iId << 5) + iId) + c; /* iId * 33 + c */
  return abs(iId);
}

int ZatData::GetChannelGroupsAmount()
{
  return channelGroups.size();
}

ZatData::ZatData(std::string u, std::string p, bool favoritesOnly,
    bool alternativeEpgService, std::string streamType) :
    maxRecallSeconds(0), recallEnabled(false), countryCode(""), recordingEnabled(
        false), updateThread(NULL), uuid("")
{
  username = u;
  password = p;
  this->alternativeEpgService = alternativeEpgService;
  this->favoritesOnly = favoritesOnly;
  m_iLastStart = 0;
  m_iLastEnd = 0;
  this->streamType = streamType;
}

ZatData::~ZatData()
{
  if (updateThread != NULL)
  {
    updateThread->StopThread(1000);
    delete updateThread;
  }
  for (auto const& item : recordingsData)
  {
    delete item.second;
  }
  channelGroups.clear();
}

bool ZatData::Initialize()
{

  if (!LoadAppId())
  {
    XBMC->Log(LOG_ERROR, "Could not get an app id.");
    return false;
  }

  if (!InitSession())
  {
    return false;
  }

  ReadDataJson();

  return true;
}

void ZatData::GetAddonCapabilities(PVR_ADDON_CAPABILITIES* pCapabilities)
{
  pCapabilities->bSupportsRecordings = recordingEnabled;
  pCapabilities->bSupportsTimers = recordingEnabled;
}

PVR_ERROR ZatData::GetChannelGroups(ADDON_HANDLE handle)
{
  std::vector<PVRZattooChannelGroup>::iterator it;
  for (it = channelGroups.begin(); it != channelGroups.end(); ++it)
  {
    PVR_CHANNEL_GROUP xbmcGroup;
    memset(&xbmcGroup, 0, sizeof(PVR_CHANNEL_GROUP));
    xbmcGroup.iPosition = 0; /* not supported  */
    xbmcGroup.bIsRadio = false; /* is radio group */
    strncpy(xbmcGroup.strGroupName, it->name.c_str(),
        sizeof(xbmcGroup.strGroupName) - 1);

    PVR->TransferChannelGroup(handle, &xbmcGroup);
  }
  return PVR_ERROR_NO_ERROR;
}

PVRZattooChannelGroup *ZatData::FindGroup(const std::string &strName)
{
  std::vector<PVRZattooChannelGroup>::iterator it;
  for (it = channelGroups.begin(); it < channelGroups.end(); ++it)
  {
    if (it->name == strName)
      return &*it;
  }

  return NULL;
}

PVR_ERROR ZatData::GetChannelGroupMembers(ADDON_HANDLE handle,
    const PVR_CHANNEL_GROUP &group)
{
  PVRZattooChannelGroup *myGroup;
  if ((myGroup = FindGroup(group.strGroupName)) != NULL)
  {
    std::vector<ZatChannel>::iterator it;
    for (it = myGroup->channels.begin(); it != myGroup->channels.end(); ++it)
    {
      ZatChannel &channel = (*it);
      PVR_CHANNEL_GROUP_MEMBER xbmcGroupMember;
      memset(&xbmcGroupMember, 0, sizeof(PVR_CHANNEL_GROUP_MEMBER));

      strncpy(xbmcGroupMember.strGroupName, group.strGroupName,
          sizeof(xbmcGroupMember.strGroupName) - 1);
      xbmcGroupMember.iChannelUniqueId = channel.iUniqueId;
      xbmcGroupMember.iChannelNumber = channel.iChannelNumber;

      PVR->TransferChannelGroupMember(handle, &xbmcGroupMember);
    }
  }

  return PVR_ERROR_NO_ERROR;
}

int ZatData::GetChannelsAmount(void)
{
  return channelsByCid.size();
}

PVR_ERROR ZatData::GetChannels(ADDON_HANDLE handle, bool bRadio)
{
  std::vector<PVRZattooChannelGroup>::iterator it;
  for (it = channelGroups.begin(); it != channelGroups.end(); ++it)
  {
    std::vector<ZatChannel>::iterator it2;
    for (it2 = it->channels.begin(); it2 != it->channels.end(); ++it2)
    {
      ZatChannel &channel = (*it2);

      PVR_CHANNEL kodiChannel;
      memset(&kodiChannel, 0, sizeof(PVR_CHANNEL));

      kodiChannel.iUniqueId = channel.iUniqueId;
      kodiChannel.bIsRadio = false;
      kodiChannel.iChannelNumber = channel.iChannelNumber;
      strncpy(kodiChannel.strChannelName, channel.name.c_str(),
          sizeof(kodiChannel.strChannelName) - 1);
      kodiChannel.iEncryptionSystem = 0;

      ostringstream iconStream;
      iconStream
          << "special://home/addons/pvr.zattoo/resources/media/channel_logo/"
          << channel.cid << ".png";
      std::string iconPath = iconStream.str();
      if (!XBMC->FileExists(iconPath.c_str(), true))
      {
        XBMC->Log(LOG_INFO,
            "No logo found for channel '%s'. Fallback to Zattoo-Logo.",
            channel.cid.c_str());
        iconPath = channel.strLogoPath;
      }

      strncpy(kodiChannel.strIconPath, iconPath.c_str(),
          sizeof(kodiChannel.strIconPath) - 1);

      kodiChannel.bIsHidden = false;

      PVR->TransferChannelEntry(handle, &kodiChannel);

    }
  }
  return PVR_ERROR_NO_ERROR;
}

std::string ZatData::GetChannelStreamUrl(int uniqueId)
{

  ZatChannel *channel = FindChannel(uniqueId);
  //XBMC->QueueNotification(QUEUE_INFO, "Getting URL for channel %s", XBMC->UnknownToUTF8(channel->name.c_str()));

  ostringstream dataStream;
  dataStream << "cid=" << channel->cid << "&stream_type=" << streamType
      << "&format=json";

  if (recallEnabled)
  {
    dataStream << "&timeshift=" << maxRecallSeconds;
  }

  string jsonString = HttpPost(zattooServer + "/zapi/watch", dataStream.str());

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    return "";
  }
  string url = doc["stream"]["url"].GetString();
  return url;

}

ZatChannel *ZatData::FindChannel(int uniqueId)
{
  std::vector<PVRZattooChannelGroup>::iterator it;
  for (it = channelGroups.begin(); it != channelGroups.end(); ++it)
  {
    std::vector<ZatChannel>::iterator it2;
    for (it2 = it->channels.begin(); it2 != it->channels.end(); ++it2)
    {
      ZatChannel &channel = (*it2);
      if (channel.iUniqueId == uniqueId)
      {
        return &channel;
      }
    }
  }
  return NULL;
}

PVR_ERROR ZatData::GetEPGForChannelExternalService(ADDON_HANDLE handle,
    const PVR_CHANNEL &channel, time_t iStart, time_t iEnd)
{
  ZatChannel *zatChannel = FindChannel(channel.iUniqueId);
  string cid = zatChannel->cid;
  ostringstream urlStream;
  urlStream << "http://zattoo.buehlmann.net/epg/api/Epg/" << countryCode << "/"
      << powerHash << "/" << cid << "/" << iStart << "/" << iEnd;
  string jsonString = HttpGet(urlStream.str());
  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError())
  {
    return PVR_ERROR_SERVER_ERROR;
  }

  for (Value::ConstValueIterator itr = doc.Begin(); itr != doc.End(); ++itr)
  {
    const Value& program = (*itr);
    EPG_TAG tag;
    memset(&tag, 0, sizeof(EPG_TAG));

    tag.iUniqueBroadcastId = program["Id"].GetInt();
    string title = program["Title"].GetString();
    tag.strTitle = title.c_str();
    tag.iUniqueChannelId = zatChannel->iUniqueId;
    tag.startTime = StringToTime(program["StartTime"].GetString());
    tag.endTime = StringToTime(program["EndTime"].GetString());
    string description = program["Description"].GetString();
    tag.strPlotOutline = description.c_str();
    tag.strPlot = description.c_str();
    tag.strOriginalTitle = NULL; /* not supported */
    tag.strCast = NULL; /* not supported */
    tag.strDirector = NULL; /*SA not supported */
    tag.strWriter = NULL; /* not supported */
    tag.iYear = 0; /* not supported */
    tag.strIMDBNumber = NULL; /* not supported */
    string imageUrl =
        program["ImageUrl"].IsString() ? program["ImageUrl"].GetString() : "";
    tag.strIconPath = imageUrl.c_str();
    tag.iParentalRating = 0; /* not supported */
    tag.iStarRating = 0; /* not supported */
    tag.bNotify = false; /* not supported */
    tag.iSeriesNumber = 0; /* not supported */
    tag.iEpisodeNumber = 0; /* not supported */
    tag.iEpisodePartNumber = 0; /* not supported */
    string subTitle =
        program["Subtitle"].IsString() ? program["Subtitle"].GetString() : "";
    tag.strEpisodeName = subTitle.c_str(); /* not supported */
    tag.iFlags = EPG_TAG_FLAG_UNDEFINED;
    string genreStr =
        program["Genre"].IsString() ? program["Genre"].GetString() : "";
    int genre = categories.Category(genreStr.c_str());
    if (genre)
    {
      tag.iGenreSubType = genre & 0x0F;
      tag.iGenreType = genre & 0xF0;
    } else
    {
      tag.iGenreType = EPG_GENRE_USE_STRING;
      tag.iGenreSubType = 0; /* not supported */
      tag.strGenreDescription = genreStr.c_str();
    }

    PVR->TransferEpgEntry(handle, &tag);
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR ZatData::GetEPGForChannel(ADDON_HANDLE handle,
    const PVR_CHANNEL &channel, time_t iStart, time_t iEnd)
{

  if (this->alternativeEpgService)
  {
    return GetEPGForChannelExternalService(handle, channel, iStart, iEnd);
  }

  ZatChannel *zatChannel = FindChannel(channel.iUniqueId);

  if (iStart > m_iLastStart || iEnd > m_iLastEnd)
  {
    // reload EPG for new time interval only
    // doesn't matter is epg loaded or not we shouldn't try to load it for same interval
    m_iLastStart = iStart;
    m_iLastEnd = iEnd;

    if (!LoadEPG(iStart, iEnd))
    {
      XBMC->Log(LOG_NOTICE,
          "Loading epg faild for channel '%s' from %lu to %lu",
          channel.strChannelName, iStart, iEnd);
      return PVR_ERROR_SERVER_ERROR;
    }
  }

  std::map<time_t, PVRIptvEpgEntry>* channelEpgCache = epgCache[zatChannel->cid];
  if (channelEpgCache == NULL)
  {
    return PVR_ERROR_NO_ERROR;
  }
  epgCache.erase(zatChannel->cid);
  for (auto const &entry : *channelEpgCache)
  {
    PVRIptvEpgEntry epgEntry = entry.second;

    EPG_TAG tag;
    memset(&tag, 0, sizeof(EPG_TAG));

    tag.iUniqueBroadcastId = epgEntry.iBroadcastId;
    tag.strTitle = epgEntry.strTitle.c_str();
    tag.iUniqueChannelId = epgEntry.iChannelId;
    tag.startTime = epgEntry.startTime;
    tag.endTime = epgEntry.endTime;
    tag.strPlotOutline = epgEntry.strPlot.c_str(); //epgEntry.strPlotOutline.c_str();
    tag.strPlot = epgEntry.strPlot.c_str();
    tag.strOriginalTitle = NULL; /* not supported */
    tag.strCast = NULL; /* not supported */
    tag.strDirector = NULL; /*SA not supported */
    tag.strWriter = NULL; /* not supported */
    tag.iYear = 0; /* not supported */
    tag.strIMDBNumber = NULL; /* not supported */
    tag.strIconPath = epgEntry.strIconPath.c_str();
    tag.iParentalRating = 0; /* not supported */
    tag.iStarRating = 0; /* not supported */
    tag.bNotify = false; /* not supported */
    tag.iSeriesNumber = 0; /* not supported */
    tag.iEpisodeNumber = 0; /* not supported */
    tag.iEpisodePartNumber = 0; /* not supported */
    tag.strEpisodeName = NULL; /* not supported */
    tag.iFlags = EPG_TAG_FLAG_UNDEFINED;

    int genre = categories.Category(epgEntry.strGenreString.c_str());
    if (genre)
    {
      tag.iGenreSubType = genre & 0x0F;
      tag.iGenreType = genre & 0xF0;
    } else
    {
      tag.iGenreType = EPG_GENRE_USE_STRING;
      tag.iGenreSubType = 0; /* not supported */
      tag.strGenreDescription = epgEntry.strGenreString.c_str();
    }

    PVR->TransferEpgEntry(handle, &tag);
  }
  delete channelEpgCache;

  return PVR_ERROR_NO_ERROR;
}

bool ZatData::LoadEPG(time_t iStart, time_t iEnd)
{
  //Do some time magic that the start date is not to far in the past because zattoo doesnt like that
  time_t tempStart = iStart - (iStart % (3600 / 2)) - 86400;
  time_t tempEnd = tempStart + 3600 * 5; //Add 5 hours

  while (tempEnd <= iEnd)
  {
    ostringstream urlStream;
    urlStream << zattooServer + "/zapi/v2/cached/program/power_guide/"
        << powerHash << "?end=" << tempEnd << "&start=" << tempStart
        << "&format=json";

    string jsonString = HttpGet(urlStream.str());

    Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError() || !doc["success"].GetBool())
    {
      return false;
    }

    const Value& channels = doc["channels"];

    //Load the channel groups and channels
    for (Value::ConstValueIterator itr = channels.Begin();
        itr != channels.End(); ++itr)
    {
      const Value& channelItem = (*itr);
      string cid = channelItem["cid"].GetString();

      int channelId = GetChannelId(cid.c_str());
      ZatChannel *channel = FindChannel(channelId);

      if (!channel)
      {
        continue;
      }

      const Value& programs = channelItem["programs"];
      for (Value::ConstValueIterator itr1 = programs.Begin();
          itr1 != programs.End(); ++itr1)
      {
        const Value& program = (*itr1);

        PVRIptvEpgEntry entry;
        entry.strTitle = program["t"].GetString();
        entry.startTime = program["s"].GetInt();
        entry.endTime = program["e"].GetInt();
        entry.iBroadcastId = program["id"].GetInt();
        entry.strIconPath =
            program["i_url"].IsString() ? program["i_url"].GetString() : "";
        entry.iChannelId = channel->iUniqueId;
        entry.strPlot =
            program["et"].IsString() ? program["et"].GetString() : "";

        const Value& genres = program["g"];
        for (Value::ConstValueIterator itr2 = genres.Begin();
            itr2 != genres.End(); ++itr2)
        {
          entry.strGenreString = (*itr2).GetString();
          break;
        }

        if (epgCache[cid] == NULL)
        {
          epgCache[cid] = new map<time_t, PVRIptvEpgEntry>();
        }
        (*epgCache[cid])[entry.startTime] = entry;
      }
    }
    tempStart = tempEnd;
    tempEnd = tempStart + 3600 * 5; //Add 5 hours
  }
  return true;
}

void ZatData::SetRecordingPlayCount(const PVR_RECORDING &recording, int count)
{
  string recordingId = recording.strRecordingId;
  ZatRecordingData *recData;
  if (recordingsData.find(recordingId) != recordingsData.end())
  {
    recData = recordingsData[recordingId];
    recData->playCount = count;
  } else
  {
    recData = new ZatRecordingData();
    recData->playCount = count;
    recData->recordingId = recordingId;
    recData->lastPlayedPosition = 0;
    recData->stillValid = true;
    recordingsData[recordingId] = recData;
  }

  WriteDataJson();
}

void ZatData::SetRecordingLastPlayedPosition(const PVR_RECORDING &recording,
    int lastplayedposition)
{
  string recordingId = recording.strRecordingId;
  ZatRecordingData *recData;
  if (recordingsData.find(recordingId) != recordingsData.end())
  {
    recData = recordingsData[recordingId];
    recData->lastPlayedPosition = lastplayedposition;
  } else
  {
    recData = new ZatRecordingData();
    recData->playCount = 0;
    recData->recordingId = recordingId;
    recData->lastPlayedPosition = lastplayedposition;
    recData->stillValid = true;
    recordingsData[recordingId] = recData;
  }

  WriteDataJson();
}

int ZatData::GetRecordingLastPlayedPosition(const PVR_RECORDING &recording)
{
  if (recordingsData.find(recording.strRecordingId) != recordingsData.end())
  {
    ZatRecordingData* recData = recordingsData[recording.strRecordingId];
    return recData->lastPlayedPosition;
  }
  return 0;
}

void ZatData::GetRecordings(ADDON_HANDLE handle, bool future)
{
  string jsonString = HttpGet(zattooServer + "/zapi/playlist");

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    return;
  }

  const Value& recordings = doc["recordings"];

  time_t current_time;
  time(&current_time);

  for (Value::ConstValueIterator itr = recordings.Begin();
      itr != recordings.End(); ++itr)
  {
    const Value& recording = (*itr);
    int programId = recording["program_id"].GetInt();
    ostringstream urlStream;
    urlStream << zattooServer + "/zapi/program/details?program_id="
        << programId;
    jsonString = HttpGet(urlStream.str());
    Document detailDoc;
    detailDoc.Parse(jsonString.c_str());
    if (detailDoc.GetParseError() || !detailDoc["success"].GetBool())
    {
      continue;
    }

    //genre
    const Value& genres = detailDoc["program"]["genres"];
    //Only get the first genre
    int genre = 0;
    if (genres.Size() > 0)
    {
      string genreName = genres[0].GetString();
      genre = categories.Category(genreName);
    }

    time_t startTime = StringToTime(recording["start"].GetString());
    if (future && startTime > current_time)
    {
      PVR_TIMER tag;
      memset(&tag, 0, sizeof(PVR_TIMER));

      tag.iClientIndex = recording["id"].GetInt();
      PVR_STRCPY(tag.strTitle, recording["title"].GetString());
      PVR_STRCPY(tag.strSummary,
          recording["episode_title"].IsString() ?
              recording["episode_title"].GetString() : "");
      time_t endTime = StringToTime(recording["end"].GetString());
      tag.startTime = startTime;
      tag.endTime = endTime;
      tag.state = PVR_TIMER_STATE_SCHEDULED;
      tag.iTimerType = 1;
      tag.iEpgUid = recording["program_id"].GetInt();
      ZatChannel channel = channelsByCid[recording["cid"].GetString()];
      tag.iClientChannelUid = channel.iUniqueId;
      PVR->TransferTimerEntry(handle, &tag);
      if (updateThread != NULL)
      {
        updateThread->SetNextRecordingUpdate(startTime);
      }
      if (genre)
      {
        tag.iGenreSubType = genre & 0x0F;
        tag.iGenreType = genre & 0xF0;
      }

    } else if (!future && startTime <= current_time)
    {
      PVR_RECORDING tag;
      memset(&tag, 0, sizeof(PVR_RECORDING));
      tag.bIsDeleted = false;

      PVR_STRCPY(tag.strRecordingId,
          to_string(recording["id"].GetInt()).c_str());
      PVR_STRCPY(tag.strTitle, recording["title"].GetString());
      PVR_STRCPY(tag.strEpisodeName,
          recording["episode_title"].IsString() ?
              recording["episode_title"].GetString() : "");
      PVR_STRCPY(tag.strPlot,
          detailDoc["program"]["description"].IsString() ?
              detailDoc["program"]["description"].GetString() : "");
      PVR_STRCPY(tag.strIconPath, recording["image_url"].GetString());
      ZatChannel channel = channelsByCid[recording["cid"].GetString()];
      tag.iChannelUid = channel.iUniqueId;
      PVR_STRCPY(tag.strChannelName, channel.name.c_str());
      time_t endTime = StringToTime(recording["end"].GetString());
      tag.recordingTime = startTime;
      tag.iDuration = endTime - startTime;

      if (genre)
      {
        tag.iGenreSubType = genre & 0x0F;
        tag.iGenreType = genre & 0xF0;
      }

      if (recordingsData.find(tag.strRecordingId) != recordingsData.end())
      {
        ZatRecordingData* recData = recordingsData[tag.strRecordingId];
        tag.iPlayCount = recData->playCount;
        tag.iLastPlayedPosition = recData->lastPlayedPosition;
        recData->stillValid = true;
      }

      PVR->TransferRecordingEntry(handle, &tag);
    }
  }
}

int ZatData::GetRecordingsAmount(bool future)
{
  string jsonString = HttpGet(zattooServer + "/zapi/playlist");

  time_t current_time;
  time(&current_time);

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    return 0;
  }

  const Value& recordings = doc["recordings"];

  int count = 0;
  for (Value::ConstValueIterator itr = recordings.Begin();
      itr != recordings.End(); ++itr)
  {
    const Value& recording = (*itr);
    time_t startTime = StringToTime(recording["start"].GetString());
    if (future == startTime > current_time)
    {
      count++;
    }
  }
  return count;
}

std::string ZatData::GetRecordingStreamUrl(string recordingId)
{
  ostringstream dataStream;
  dataStream << "recording_id=" << recordingId << "&stream_type=" << streamType;

  string jsonString = HttpPost(zattooServer + "/zapi/watch", dataStream.str());

  Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.GetParseError() || !doc["success"].GetBool())
  {
    return "";
  }

  string url = doc["stream"]["url"].GetString();
  return url;

}

bool ZatData::Record(int programId)
{
  ostringstream dataStream;
  dataStream << "program_id=" << programId;

  string jsonString = HttpPost(zattooServer + "/zapi/playlist/program",
      dataStream.str());
  Document doc;
  doc.Parse(jsonString.c_str());
  return !doc.GetParseError() && doc["success"].GetBool();
}

bool ZatData::DeleteRecording(string recordingId)
{
  ostringstream dataStream;
  dataStream << "recording_id=" << recordingId << "";

  string jsonString = HttpPost(zattooServer + "/zapi/playlist/remove",
      dataStream.str());

  Document doc;
  doc.Parse(jsonString.c_str());
  return !doc.GetParseError() && doc["success"].GetBool();
}

bool ZatData::IsPlayable(const EPG_TAG *tag)
{
  if (!recallEnabled)
  {
    return false;
  }
  time_t current_time;
  time(&current_time);
  return ((current_time - tag->endTime) < maxRecallSeconds)
      && (tag->startTime < current_time);
}

bool ZatData::IsRecordable(const EPG_TAG *tag)
{
  time_t current_time;
  time(&current_time);
  if (!recallEnabled)
  {
    return current_time < tag->startTime;
  }
  return ((current_time - tag->endTime) < maxRecallSeconds);
}

string ZatData::GetEpgTagUrl(const EPG_TAG *tag)
{
  ostringstream dataStream;
  ZatChannel channel = channelsByUid[tag->iUniqueChannelId];
  char timeStart[sizeof "2011-10-08T07:07:09Z"];
  strftime(timeStart, sizeof timeStart, "%FT%TZ", gmtime(&tag->startTime));
  char timeEnd[sizeof "2011-10-08T07:07:09Z"];
  strftime(timeEnd, sizeof timeEnd, "%FT%TZ", gmtime(&tag->endTime));

  dataStream << "cid=" << channel.cid << "&start=" << timeStart << "&end="
      << timeEnd << "&stream_type=" << streamType;

  string jsonString = HttpPost(zattooServer + "/zapi/watch", dataStream.str());

  Document doc;
  doc.Parse(jsonString.c_str());
  return doc["stream"]["url"].GetString();
}

time_t ZatData::StringToTime(string timeString)
{
  struct tm *tm;
  time_t current_time;
  time(&current_time);
  tm = localtime(&current_time);

  int year, month, day, h, m, s;
  sscanf(timeString.c_str(), "%d-%d-%dT%d:%d:%dZ", &year, &month, &day, &h, &m,
      &s);
  tm->tm_year = year - 1900;
  tm->tm_mon = month - 1;
  tm->tm_mday = day;
  tm->tm_hour = h;
  tm->tm_min = m;
  tm->tm_sec = s;

  return timegm(tm);
}
