#include "MDNS.h"

Buffer::Buffer(uint16_t size) {
  this->data = (uint8_t *) malloc(size);
  this->size = data != NULL? size : 0;
}

uint16_t Buffer::available() {
  return offset < limit? limit - offset : offset - limit;
}

void Buffer::mark() {
  if (markOffset == INVALID_MARK_OFFSET) {
    markOffset = offset;
  }
}

void Buffer::reset() {
  if (markOffset != INVALID_MARK_OFFSET) {
    offset = markOffset;
    markOffset = INVALID_MARK_OFFSET;
  }
}

void Buffer::setOffset(uint16_t offset) {
  this->offset = offset;
}

uint16_t Buffer::getOffset() {
  return offset;
}

void Buffer::read(UDP * udp) {
  offset = 0;
  limit = udp->read(data, size);
}

uint8_t Buffer::readUInt8() {
  return data[offset++];
}

uint16_t Buffer::readUInt16() {
  return readUInt8() << 8 | readUInt8();
}

void Buffer::writeUInt8(uint8_t value) {
  if (offset < size) {
    data[offset++] = value;
  }
}

void Buffer::writeUInt16(uint16_t value) {
  writeUInt8(value >> 8);
  writeUInt8(value);
}

void Buffer::writeUInt32(uint32_t value) {
  writeUInt8(value >> 24);
  writeUInt8(value >> 16);
  writeUInt8(value >> 8);
  writeUInt8(value);
}

void Buffer::write(UDP * udp) {
  udp->write(data, offset);

  offset = 0;
}

void Buffer::clear() {
  offset = 0;
  limit = 0;
}

Record::Record(uint16_t type, uint32_t ttl) {
  this->type = type;
  this->ttl = ttl;
}

void Record::setLabel(Label * label) {
  this->label = label;
}

void Record::setAnswerRecord() {
  this->answerRecord = true;
}

bool Record::isAnswerRecord() {
  return answerRecord && !knownRecord;
}

void Record::setAdditionalRecord() {
  this->additionalRecord = true;
}

bool Record::isAdditionalRecord() {
  return additionalRecord && !answerRecord && !knownRecord;
}

void Record::setKnownRecord() {
  this->knownRecord = true;
}

void Record::write(Buffer * buffer) {
  label->write(buffer);
  buffer->writeUInt16(type);
  buffer->writeUInt16(IN_CLASS);
  buffer->writeUInt32(ttl);
  writeSpecific(buffer);
}

void Record::reset() {
  this->answerRecord = false;
  this->additionalRecord = false;
  this->knownRecord = false;
}

Label * Record::getLabel() {
  return label;
}

ARecord::ARecord():Record(A_TYPE, TTL_2MIN) {
}

void ARecord::writeSpecific(Buffer * buffer) {
  buffer->writeUInt16(4);
  IPAddress ip = WiFi.localIP();
  for (int i = 0; i < IP_SIZE; i++) {
    buffer->writeUInt8(ip[i]);
  }
}

NSECRecord::NSECRecord():Record(NSEC_TYPE, TTL_2MIN) {
}

HostNSECRecord::HostNSECRecord():NSECRecord() {
}

void HostNSECRecord::writeSpecific(Buffer * buffer) {
  buffer->writeUInt16(5);
  getLabel()->write(buffer);
  buffer->writeUInt8(0);
  buffer->writeUInt8(1);
  buffer->writeUInt8(0x40);
}

InstanceNSECRecord::InstanceNSECRecord():NSECRecord() {
}

void InstanceNSECRecord::writeSpecific(Buffer * buffer) {
  buffer->writeUInt16(9);
  getLabel()->write(buffer);
  buffer->writeUInt8(0);
  buffer->writeUInt8(5);
  buffer->writeUInt8(0);
  buffer->writeUInt8(0);
  buffer->writeUInt8(0x80);
  buffer->writeUInt8(0);
  buffer->writeUInt8(0x40);
}

PTRRecord::PTRRecord():Record(PTR_TYPE, TTL_75MIN) {
}

void PTRRecord::writeSpecific(Buffer * buffer) {
  buffer->writeUInt16(instanceLabel->getWriteSize());
  instanceLabel->write(buffer);
}

void PTRRecord::setInstanceLabel(Label * label) {
  instanceLabel = label;
}

SRVRecord::SRVRecord():Record(SRV_TYPE, TTL_2MIN) {
}

void SRVRecord::writeSpecific(Buffer * buffer) {
  buffer->writeUInt16(6 + hostLabel->getWriteSize());
  buffer->writeUInt16(0);
  buffer->writeUInt16(0);
  buffer->writeUInt16(port);
  hostLabel->write(buffer);
}

void SRVRecord::setHostLabel(Label * label) {
  hostLabel = label;
}

void SRVRecord::setPort(uint16_t port) {
  this->port = port;
}

TXTRecord::TXTRecord():Record(TXT_TYPE, TTL_75MIN) {
}

void TXTRecord::addEntry(String key, String value) {
  String entry = key;

  if (value != NULL) {
    entry += '=';
    entry += value;
  }

  data.push_back(entry);
}

void TXTRecord::writeSpecific(Buffer * buffer) {
  uint16_t size = 0;

  std::vector<String>::const_iterator i;

  for(i = data.begin(); i != data.end(); ++i) {
    size += i->length() + 1;
  }

  buffer->writeUInt16(size);

  for(i = data.begin(); i != data.end(); ++i) {
    uint8_t length = i->length();

    buffer->writeUInt8(length);

    for (uint8_t idx = 0; idx < length; idx++) {
      buffer->writeUInt8(i->charAt(idx));
    }
  }
}

Label::Label(String name, Label * nextLabel, bool caseSensitive) {
  data = (uint8_t *) malloc(name.length() + 1);

  if (data) {
    data[0] = name.length();
    for (uint8_t i = 0; i < name.length(); i++) {
      data[i + 1] = name.charAt(i);
    }
  } else {
    data = EMPTY_DATA;
  }

  this->nextLabel = nextLabel;
  this->caseSensitive = caseSensitive;
}

uint8_t Label::getSize() {
  return data[0];
}

uint8_t Label::getWriteSize() {
  Label * label = this;
  uint8_t size = 0;

  while (label != NULL) {
    if (label->writeOffset == INVALID_OFFSET) {
      size += label->data[0] + 1;
      label = label->nextLabel;
    } else {
      size += 2;
      label = NULL;
    }
  }

  return size;
}

void Label::write(Buffer * buffer) {
  Label * label = this;

  while (label) {
    if (label->writeOffset == INVALID_OFFSET) {
      label->writeOffset = buffer->getOffset();

      uint8_t size = label->data[0] + 1;

      for (uint8_t i = 0; i < size; i++) {
        buffer->writeUInt8(label->data[i]);
      }

      label = label->nextLabel;
    } else {
      buffer->writeUInt16((LABEL_POINTER << 8) | label->writeOffset);
      label = NULL;
    }
  }
}

void Label::reset() {
  Label * label = this;

  while (label != NULL) {
    label->writeOffset = INVALID_OFFSET;

    label = label->nextLabel;
  }
}

Label::Reader::Reader(Buffer * buffer) {
  this->buffer = buffer;
}

bool Label::Reader::hasNext() {
  return c != END_OF_NAME && buffer->available() > 0;
}

uint8_t Label::Reader::next() {
  c = buffer->readUInt8();

  while ((c & LABEL_POINTER) == LABEL_POINTER) {
    if (buffer->available() > 0) {
      uint8_t c2 = buffer->readUInt8();

      uint16_t pointerOffset = ((c & ~LABEL_POINTER) << 8) | c2;

      buffer->mark();

      buffer->setOffset(pointerOffset);

      c = buffer->readUInt8();
    }
  }

  return c;
}

bool Label::Reader::endOfName() {
  return c == END_OF_NAME;
}

Label::Iterator::Iterator(Label * label) {
  this->label = label;
  this->startLabel = label;
  this->size = label->data[0];
}

bool Label::Iterator::match(uint8_t c) {
  if (matches) {
    while (offset > size && label) {
      label = label->nextLabel;
      size = label->data[0];
      offset = 0;
    }

    matches = offset <= size && label && (label->data[offset] == c || (!label->caseSensitive && equalsIgnoreCase(c)));

    offset++;
  }

  return matches;
}

bool Label::Iterator::matched() {
  return matches;
}

bool Label::Iterator::equalsIgnoreCase(uint8_t c) {
  return (c >= 'a' && c <= 'z' && label->data[offset] == c - 32) || (c >= 'A' && c <= 'Z' && label->data[offset] == c + 32);
}

Label * Label::Iterator::getStartLabel() {
  return startLabel;
}

Label * Label::Matcher::match(std::map<String, Label *> labels, Buffer * buffer) {

  Iterator * iterators[labels.size()];

  std::map<String, Label *>::const_iterator i;

  uint8_t idx = 0;

  for (i = labels.begin(); i != labels.end(); ++i) {
    iterators[idx++] = new Iterator(i->second);
  }

  Reader * reader = new Reader(buffer);

  while (reader->hasNext()) {
    uint8_t size = reader->next();

    uint8_t idx = 0;

    for (uint8_t i = 0; i < labels.size(); i++) {
      iterators[i]->match(size);
    }

    while(idx < size && reader->hasNext()) {
      uint8_t c = reader->next();

      for (uint8_t i = 0; i < labels.size(); i++) {
        iterators[i]->match(c);
      }

      idx++;
    }
  }


  buffer->reset();

  Label * label = NULL;

  if (reader->endOfName()) {
    uint8_t idx = 0;

    while (label == NULL && idx < labels.size()) {
      if (iterators[idx]->matched()) {
        label = iterators[idx]->getStartLabel();
      }

      idx++;
    }
  }

  for (uint8_t i = 0; i < labels.size(); i++) {
    delete iterators[i];
  }

  delete reader;

  return label;
}

void Label::matched(uint16_t type, uint16_t cls) {
}

HostLabel::HostLabel(Record * aRecord, Record * nsecRecord, String name, Label * nextLabel, bool caseSensitive):Label(name, nextLabel, caseSensitive) {
  this->aRecord = aRecord;
  this->nsecRecord = nsecRecord;
}

void HostLabel::matched(uint16_t type, uint16_t cls) {
  switch(type) {
    case A_TYPE:
    case ANY_TYPE:
    aRecord->setAnswerRecord();
    nsecRecord->setAdditionalRecord();
    break;

    default:
    nsecRecord->setAnswerRecord();
  }
}

ServiceLabel::ServiceLabel(Record * aRecord, String name, Label * nextLabel, bool caseSensitive):Label(name, nextLabel, caseSensitive) {
  this->aRecord = aRecord;
}

void ServiceLabel::addInstance(Record * ptrRecord, Record * srvRecord, Record * txtRecord) {
    ptrRecords.push_back(ptrRecord);
    srvRecords.push_back(srvRecord);
    txtRecords.push_back(txtRecord);
}

void ServiceLabel::matched(uint16_t type, uint16_t cls) {
  switch(type) {
    case PTR_TYPE:
    case ANY_TYPE:
    for (std::vector<Record *>::const_iterator i = ptrRecords.begin(); i != ptrRecords.end(); ++i) {
      (*i)->setAnswerRecord();
    }
    for (std::vector<Record *>::const_iterator i = srvRecords.begin(); i != srvRecords.end(); ++i) {
      (*i)->setAdditionalRecord();
    }
    for (std::vector<Record *>::const_iterator i = txtRecords.begin(); i != txtRecords.end(); ++i) {
      (*i)->setAdditionalRecord();
    }
    aRecord->setAdditionalRecord();
    break;
  }
}

InstanceLabel::InstanceLabel(Record * srvRecord, Record * txtRecord, Record * nsecRecord, Record * aRecord, String name, Label * nextLabel, bool caseSensitive):Label(name, nextLabel, caseSensitive) {
  this->srvRecord = srvRecord;
  this->txtRecord = txtRecord;
  this->nsecRecord = nsecRecord;
  this->aRecord = aRecord;
}

void InstanceLabel::matched(uint16_t type, uint16_t cls) {
  switch(type) {
    case SRV_TYPE:
    srvRecord->setAnswerRecord();
    txtRecord->setAdditionalRecord();
    nsecRecord->setAdditionalRecord();
    aRecord->setAdditionalRecord();
    break;

    case TXT_TYPE:
    txtRecord->setAnswerRecord();
    srvRecord->setAdditionalRecord();
    nsecRecord->setAdditionalRecord();
    aRecord->setAdditionalRecord();
    break;

    case ANY_TYPE:
    srvRecord->setAnswerRecord();
    txtRecord->setAnswerRecord();
    nsecRecord->setAdditionalRecord();
    aRecord->setAdditionalRecord();
    break;

    default:
    nsecRecord->setAnswerRecord();
  }
}

bool MDNS::setHostname(String hostname) {
  bool success = true;
  String status = "Ok";

  if (labels[HOSTNAME]) {
    status = "Hostname already set";
    success = false;
  }

  if (success && hostname.length() < MAX_LABEL_SIZE && isAlphaDigitHyphen(hostname)) {
    aRecord = new ARecord();

    HostNSECRecord * hostNSECRecord = new HostNSECRecord();

    records.push_back(aRecord);
    records.push_back(hostNSECRecord);

    Label * label = new HostLabel(aRecord, hostNSECRecord, hostname, LOCAL);

    labels[HOSTNAME] = label;

    aRecord->setLabel(label);
    hostNSECRecord->setLabel(label);
  } else {
    status = success? "Invalid hostname" : status;
    success = false;
  }

  return success;
}

bool MDNS::addService(String protocol, String service, uint16_t port, String instance, std::vector<String> subServices) {
  bool success = true;
  String status = "Ok";

  if (!labels[HOSTNAME]) {
    status = "Hostname not set";
    success = false;
  }

  if (success && protocol.length() < MAX_LABEL_SIZE - 1 && service.length() < MAX_LABEL_SIZE - 1 &&
  instance.length() < MAX_LABEL_SIZE && isAlphaDigitHyphen(protocol) && isAlphaDigitHyphen(service) && isNetUnicode(instance)) {

    PTRRecord * ptrRecord = new PTRRecord();
    SRVRecord * srvRecord = new SRVRecord();
    txtRecord = new TXTRecord();
    InstanceNSECRecord * instanceNSECRecord = new InstanceNSECRecord();

    records.push_back(ptrRecord);
    records.push_back(srvRecord);
    records.push_back(txtRecord);
    records.push_back(instanceNSECRecord);

    String serviceString = "_" + service + "._" + protocol;

    Label * protocolLabel = new Label("_" + protocol, LOCAL);

    if (labels[serviceString] == NULL) {
      labels[serviceString] = new ServiceLabel(aRecord, "_" + service, protocolLabel);
    }

    ((ServiceLabel *) labels[serviceString])->addInstance(ptrRecord, srvRecord, txtRecord);

    String instanceString = instance + "._" + service + "._" + protocol;

    labels[instanceString] = new InstanceLabel(srvRecord, txtRecord, instanceNSECRecord, aRecord, instance, labels[serviceString], true);

    for (std::vector<String>::const_iterator i = subServices.begin(); i != subServices.end(); ++i) {
      String subServiceString = "_" + *i + "._sub." + serviceString;

      if (labels[subServiceString] == NULL) {
        labels[subServiceString] = new ServiceLabel(aRecord, "_" + *i, new Label("_sub", labels[serviceString]));
      }

      PTRRecord * subPTRRecord = new PTRRecord();

      subPTRRecord->setLabel(labels[subServiceString]);
      subPTRRecord->setInstanceLabel(labels[instanceString]);

      records.push_back(subPTRRecord);

      ((ServiceLabel *) labels[subServiceString])->addInstance(subPTRRecord, srvRecord, txtRecord);
    }

    ptrRecord->setLabel(labels[serviceString]);
    ptrRecord->setInstanceLabel(labels[instanceString]);
    srvRecord->setLabel(labels[instanceString]);
    srvRecord->setPort(port);
    srvRecord->setHostLabel(labels[HOSTNAME]);
    txtRecord->setLabel(labels[instanceString]);
    instanceNSECRecord->setLabel(labels[instanceString]);
  } else {
    status = success? "Invalid name" : status;
    success = false;
  }

  return success;
}

void MDNS::addTXTEntry(String key, String value) {
  txtRecord->addEntry(key, value);
}

bool MDNS::begin() {
  // Wait for WiFi to connect
  while (!WiFi.ready()) {
  }

  udp->begin(MDNS_PORT);
  udp->joinMulticast(IPAddress(224, 0, 0, 251));

  // TODO: Probing + announcing

  return true;
}

bool MDNS::processQueries() {
  uint16_t n = udp->parsePacket();

  if (n > 0) {
    buffer->read(udp);

    udp->flush();

    getResponses();

    buffer->clear();

    writeResponses();

    if (buffer->available() > 0) {
      udp->beginPacket(IPAddress(224, 0, 0, 251), MDNS_PORT);

      buffer->write(udp);

      udp->endPacket();
    }
  }

  return n > 0;
}

void MDNS::getResponses() {
  QueryHeader header = readHeader(buffer);

  if ((header.flags & 0x8000) == 0 && header.qdcount > 0) {
    uint8_t count = 0;

    while (count++ < header.qdcount && buffer->available() > 0) {
      Label * label = matcher->match(labels, buffer);

      if (buffer->available() >= 4) {
        uint16_t type = buffer->readUInt16();
        uint16_t cls = buffer->readUInt16();

        if (label != NULL) {

          label->matched(type, cls);
        }
      } else {
        status = "Buffer underflow at index " + buffer->getOffset();
      }
    }
  }
}

MDNS::QueryHeader MDNS::readHeader(Buffer * buffer) {
  QueryHeader header;

  if (buffer->available() >= 12) {
    header.id = buffer->readUInt16();
    header.flags = buffer->readUInt16();
    header.qdcount = buffer->readUInt16();
    header.ancount = buffer->readUInt16();
    header.nscount = buffer->readUInt16();
    header.arcount = buffer->readUInt16();
  }

  return header;
}

void MDNS::writeResponses() {

  uint8_t answerCount = 0;
  uint8_t additionalCount = 0;

  for (std::vector<Record *>::const_iterator i = records.begin(); i != records.end(); ++i) {
    if ((*i)->isAnswerRecord()) {
      answerCount++;
    }
    if ((*i)->isAdditionalRecord()) {
      additionalCount++;
    }
  }

  if (answerCount > 0) {
    buffer->writeUInt16(0x0);
    buffer->writeUInt16(0x8400);
    buffer->writeUInt16(0x0);
    buffer->writeUInt16(answerCount);
    buffer->writeUInt16(0x0);
    buffer->writeUInt16(additionalCount);

    for (std::vector<Record *>::const_iterator i = records.begin(); i != records.end(); ++i) {
      if ((*i)->isAnswerRecord()) {
        (*i)->write(buffer);
      }
    }

    for (std::vector<Record *>::const_iterator i = records.begin(); i != records.end(); ++i) {
      if ((*i)->isAdditionalRecord()) {
        (*i)->write(buffer);
      }
    }
  }

  for (std::map<String, Label *>::const_iterator i = labels.begin(); i != labels.end(); ++i) {
    i->second->reset();
  }

  for (std::vector<Record *>::const_iterator i = records.begin(); i != records.end(); ++i) {
    (*i)->reset();
  }
}

bool MDNS::isAlphaDigitHyphen(String string) {
  bool result = true;

  uint8_t idx = 0;

  while (result && idx < string.length()) {
    uint8_t c = string.charAt(idx++);

    result = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
  }

  return result;
}

bool MDNS::isNetUnicode(String string) {
  bool result = true;

  uint8_t idx = 0;

  while (result && idx < string.length()) {
    uint8_t c = string.charAt(idx++);

    result = c >= 0x1f && c != 0x7f;
  }

  return result;
}
