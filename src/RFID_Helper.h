/***************************************************
This is a helper library for MFRC522
****************************************************/

#include <SPI.h>                      // RFID MFRC522 Module uses SPI protocol
#include <MFRC522.h>                  // Library for Mifare RC522 Device

class RFID_Helper {
public:
  void start(void);
  void setKey(void);
  byte getKeySize(void);
  byte *getKey(void);
  bool selectCard(void);
  uint32_t getUID(void);
  MFRC522::PICC_Type  getType(void);
  static const __FlashStringHelper *getTypeName(void);
  bool isCompatible(void);
  bool authenticate(void);
  bool read(byte addr, byte *buffer);
  bool write(byte addr, byte *data);
  void dumpSector(byte sector);

  void stop(void);
  void dumpByteArray(byte *buffer, byte bufferSize);

  bool writeString(byte addr, String &str);
  bool readString(byte addr, String &str);

private:
  uint32_t int_big_endian(uint8_t *arr, size_t n);

  byte trailerBlock   = 7;
  MFRC522::StatusCode status;
  byte buffer[18];
};
