/***************************************************
  This is a helper library for MFRC522
 ****************************************************/

#include "RFID_Helper.h"

// Create MFRC522 RFID instance
MFRC522 mfrc522 = MFRC522();
MFRC522::MIFARE_Key key;

// Init
void RFID_Helper::start(){
  SPI.begin();        // Init SPI bus
  mfrc522.PCD_Init(); // Init MFRC522 card
}

void RFID_Helper::setKey(){
  // Prepare the key (used both as key A and as key B)
  // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
  for (byte i = 0; i < 6; i++) {
      key.keyByte[i] = 0xFF;
  }
}

byte RFID_Helper::getKeySize(){
  return MFRC522::MF_KEY_SIZE;
}

byte *RFID_Helper::getKey(){
  return key.keyByte;
}

bool RFID_Helper::selectCard(){
  // Look for new cards
  if (!mfrc522.PICC_IsNewCardPresent())
      return false;
  // Select one of the cards
  if (!mfrc522.PICC_ReadCardSerial())
      return false;

  return true;
}

// Utility
uint32_t RFID_Helper::int_big_endian(uint8_t *arr, size_t n)
{
    uint64_t res = 0ul;
    while (n--) res = res << 8 | *arr++;
    return res;
}

uint32_t RFID_Helper::getUID(){
  return int_big_endian(mfrc522.uid.uidByte, mfrc522.uid.size);
}

MFRC522::PICC_Type RFID_Helper::getType(){
  return mfrc522.PICC_GetType(mfrc522.uid.sak);
}

const __FlashStringHelper *RFID_Helper::getTypeName(){
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  return mfrc522.PICC_GetTypeName(piccType);
}

bool RFID_Helper::isCompatible(){
  // Check for compatibility
  MFRC522::PICC_Type piccType = getType();
  if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
      &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
      &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
      Serial.println(F("This sample only works with MIFARE Classic cards."));
      return false;
  }
  return true;
}

bool RFID_Helper::authenticate(){
  // Authenticate using key
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
      Serial.print(F("PCD_Authenticate() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
  }
  return true;
}

bool RFID_Helper::read(byte addr, byte *buffer){
  byte size = 18; // sizeof(buffer);
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(addr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
  }
  return true;
}

bool RFID_Helper::write(byte addr, byte *buffer){
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(addr, buffer, 16);
  if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
  }
  return true;
}

void RFID_Helper::dumpSector(byte sector){
  mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
}

void RFID_Helper::stop(){
  // Halt PICC
  mfrc522.PICC_HaltA();
  // Stop encryption on PCD
  mfrc522.PCD_StopCrypto1();
}

// Dump a byte array as hex values to Serial.
void RFID_Helper::dumpByteArray(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

// Write to block
bool RFID_Helper::writeString(byte addr, String &str){
  // Check for compatibility
  if (!isCompatible()) {
      Serial.println(F("This sample only works with MIFARE Classic cards."));
      return false;
  }
  // Authenticate
  if(addr%4 == 3){
    Serial.println(F("The block is protected."));
    return false;
  }
  trailerBlock = addr + 3;
  if(!authenticate())
    return false;
  // Write to the block
  byte buffer[18];
  strcpy(reinterpret_cast<char*>(buffer), str.c_str());
  if(!write(addr, buffer))
    return false;

  return true;
}

// Write to block
bool RFID_Helper::readString(byte addr, String &str){
  // Check for compatibility
  if (!isCompatible()) {
      Serial.println(F("This sample only works with MIFARE Classic cards."));
      return false;
  }
  // Authenticate
  if(addr%4 == 3){
    Serial.println(F("The block is protected."));
    return false;
  }
  trailerBlock = addr + 3;
  if(!authenticate())
    return false;
  // Read from the block
  byte buffer[18];
  if(!read(addr, buffer))
    return false;

  str = String(reinterpret_cast<char*>(buffer));
  return true;
}
