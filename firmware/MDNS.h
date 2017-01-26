#include "Particle.h"
#include <map>
#include <vector>

#ifndef _INCL_BUFFER
#define _INCL_BUFFER

#define INVALID_MARK_OFFSET 0xffff

class Buffer {
public:
  Buffer(uint16_t size);

  uint16_t available();

  void mark();
  void reset();
  void setOffset(uint16_t offset);
  uint16_t getOffset();

  void read(UDP * udp);

  uint8_t readUInt8();
  uint16_t readUInt16();

  void write(UDP * udp);

  void writeUInt8(uint8_t value);
  void writeUInt16(uint16_t value);
  void writeUInt32(uint32_t value);

  void clear();

private:

  uint8_t * data;
  uint16_t size;

  uint16_t limit = 0;
  uint16_t offset = 0;
  uint16_t markOffset = INVALID_MARK_OFFSET;
};

#endif

#ifndef _INCL_RECORD
#define _INCL_RECORD

#define IN_CLASS 1

#define A_TYPE 0x01
#define PTR_TYPE 0x0c
#define TXT_TYPE 0x10
#define AAAA_TYPE 0x1c
#define SRV_TYPE 0x21
#define NSEC_TYPE 0x2f

#define ANY_TYPE 0xFF

#define TTL_2MIN 120
#define TTL_75MIN 4500

#define IP_SIZE 4

class Label;

class Record {

public:

  void setLabel(Label * label);

  void setAnswerRecord();

  bool isAnswerRecord();

  void setAdditionalRecord();

  bool isAdditionalRecord();

  void setKnownRecord();

  void write(Buffer * buffer);

  void reset();

protected:

  Record(uint16_t type, uint32_t ttl);

  Label * getLabel();

  virtual void writeSpecific(Buffer * buffer) = 0;

private:

  Label * label;
  uint16_t type;
  uint32_t ttl;
  bool answerRecord = false;
  bool additionalRecord = false;
  bool knownRecord = false;
};

class ARecord : public Record {

public:

  ARecord();

  virtual void writeSpecific(Buffer * buffer);
};

class NSECRecord : public Record {

public:

  NSECRecord();

  virtual void writeSpecific(Buffer * buffer) = 0;
};

class HostNSECRecord : public NSECRecord {

public:

  HostNSECRecord();

  virtual void writeSpecific(Buffer * buffer);
};

class InstanceNSECRecord : public NSECRecord {

public:

  InstanceNSECRecord();

  virtual void writeSpecific(Buffer * buffer);
};

class PTRRecord : public Record {

public:

  PTRRecord();

  virtual void writeSpecific(Buffer * buffer);

  void setInstanceLabel(Label * label);

private:

  Label * instanceLabel;

};

class SRVRecord : public Record {

public:

  SRVRecord();

  virtual void writeSpecific(Buffer * buffer);

  void setHostLabel(Label * label);

  void setPort(uint16_t port);

private:

  Label * hostLabel;
  uint16_t port;
};

class TXTRecord : public Record {

public:

  TXTRecord();

  virtual void writeSpecific(Buffer * buffer);

  void addEntry(String key, String value = NULL);

private:

  std::vector<String> data;
};

#endif

#ifndef _INCL_LABEL
#define _INCL_LABEL

#define DOT '.'

#define END_OF_NAME 0x0
#define LABEL_POINTER 0xc0
#define MAX_LABEL_SIZE 63
#define INVALID_OFFSET -1

#define UNKNOWN_NAME -1
#define BUFFER_UNDERFLOW -2

class Label {
private:

  class Iterator;

public:
  class Matcher {
  public:
    Label * match(std::map<String, Label *> labels, Buffer * buffer);
  };

  Label(String name, Label * nextLabel = NULL, bool caseSensitive = false);

  uint8_t getSize();

  uint8_t getWriteSize();

  void write(Buffer * buffer);

  virtual void matched(uint16_t type, uint16_t cls);

  void reset();

private:
  class Reader {
  public:
    Reader(Buffer * buffer);

    bool hasNext();

    uint8_t next();

    bool endOfName();
  private:
    Buffer * buffer;
    uint8_t c = 1;
  };

  class Iterator {
  public:
    Iterator(Label * label);

    bool match(uint8_t c);

    bool matched();

    Label * getStartLabel();

  private:
    Label * startLabel;
    Label * label;
    uint8_t size;
    uint8_t offset = 0;
    bool matches = true;

    bool equalsIgnoreCase(uint8_t c);
  };

  uint8_t * EMPTY_DATA = { END_OF_NAME };
  uint8_t * data;
  bool caseSensitive;
  Label * nextLabel;
  int16_t writeOffset = INVALID_OFFSET;
};

class HostLabel : public Label {

public:

  HostLabel(Record * aRecord, Record * nsecRecord, String name, Label * nextLabel = NULL, bool caseSensitive = false);

  virtual void matched(uint16_t type, uint16_t cls);

private:
  Record * aRecord;
  Record * nsecRecord;
};

class ServiceLabel : public Label {

public:

  ServiceLabel(Record * aRecord, String name, Label * nextLabel = NULL, bool caseSensitive = false);

  void addInstance(Record * ptrRecord, Record * srvRecord, Record * txtRecord);

  virtual void matched(uint16_t type, uint16_t cls);

private:
  Record * aRecord;
  std::vector<Record *> ptrRecords;
  std::vector<Record *> srvRecords;
  std::vector<Record *> txtRecords;
};

class InstanceLabel : public Label {

public:

  InstanceLabel(Record * srvRecord, Record * txtRecord, Record * nsecRecord, Record * aRecord, String name, Label * nextLabel = NULL, bool caseSensitive = false);

  virtual void matched(uint16_t type, uint16_t cls);

private:
  Record * srvRecord;
  Record * txtRecord;
  Record * nsecRecord;
  Record * aRecord;
};

#endif


#ifndef _INCL_MDNS
#define _INCL_MDNS

#define MDNS_PORT 5353

#define BUFFER_SIZE 512
#define HOSTNAME ""

class MDNS {
public:

  bool setHostname(String hostname);

  bool addService(String protocol, String service, uint16_t port, String instance, std::vector<String> subServices = std::vector<String>());

  void addTXTEntry(String key, String value = NULL);

  bool begin();

  bool processQueries();

private:

  struct QueryHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
  };

  UDP * udp = new UDP();
  Buffer * buffer = new Buffer(BUFFER_SIZE);

  Label * ROOT = new Label("");
  Label * LOCAL = new Label("local", ROOT);
  Label::Matcher * matcher = new Label::Matcher();

  ARecord * aRecord;
  TXTRecord * txtRecord;

  std::map<String, Label *> labels;
  std::vector<Record *> records;
  String status = "Ok";

  QueryHeader readHeader(Buffer * buffer);
  void getResponses();
  void writeResponses();
  bool isAlphaDigitHyphen(String string);
  bool isNetUnicode(String string);
};

#endif
