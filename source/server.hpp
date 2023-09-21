#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <unistd.h>

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
public:
    Buffer() : buffer_(BUFFER_DEFAULT_SIZE), reader_offset_(0), writer_offset_(0) {}
    char *ReaderPosition() { return &(*buffer_.begin()) + reader_offset_; }
    char *WriterPosition() { return &(*buffer_.begin()) + writer_offset_; }
    uint64_t ReadalbeSize() { return writer_offset_ - reader_offset_; }
    uint64_t HeadWritableSize() { return reader_offset_; }
    uint64_t TailWritableSize() { return buffer_.size() - writer_offset_; }
    void MoveReaderOffset(uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadalbeSize());
        writer_offset_ += len;
    }
    void MoveWriterOffset(uint64_t len) {
        if (len == 0) return;
        assert(len <= TailWritableSize());
        writer_offset_ += len;
    }
    void EnsureWritableSpaceEnough(uint64_t len) {
        if (len == 0) return;
        if (len <= TailWritableSize()) {
            return;
        } else if (len <= HeadWritableSize() + TailWritableSize()) {
            std::copy(ReaderPosition(), WriterPosition(), buffer_.begin());
            reader_offset_ = 0;
            writer_offset_ = ReadalbeSize();
        } else {
            buffer_.resize(writer_offset_ + len);
        }
    }
    void Write(const void *data, uint64_t len) {
        if (len == 0) return;
        EnsureWritableSpaceEnough(len);
        std::copy((const char *)data, (const char *)data + len, WriterPosition());
    }
    void WriteAndPushOffSet(const void *data, uint64_t len) {
        if (len == 0) return;
        Write(data, len);
        MoveWriterOffset(len);
    }
    void WriteString(const std::string &str) {
        if (str.size() == 0) return;
        Write(str.c_str(), str.size());
    }
    void WriteStringAndPushOffSet(const std::string &str) {
        if (str.size() == 0) return;
        WriteString(str);
        MoveWriterOffset(str.size());
    }
    void WriteBuffer(const Buffer &buf) {
        if (buf.ReadalbeSize() == 0) return;
        Write(buf.ReaderPosition(), buf.ReadalbeSize());
    }
    void WriteBufferAndPushOffSet(const Buffer &buf) {
        if (buf.ReadalbeSize() == 0) return;
        WriteBuffer(buf);
        MoveWriterOffset(buf.ReadalbeSize());
    }
    void Read(void *buf, uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadalbeSize());
        std::copy(ReaderPosition(), ReaderPosition() + ReadalbeSize(), (char *)buf);
    }
    void ReadAndPushOffSet(void *buf, uint64_t len) {
        if (len == 0) return;
        Read(buf, len);
        MoveReaderOffset(len);
    }
    std::string ReadAsString(uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadalbeSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str; 
    }
    std::string ReadAsStringAndPushOffSet(uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadalbeSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    std::string GetLine() {
        char *pos = (char *)memchr(ReaderPosition(), '\n', ReadalbeSize());
        if (pos == nullptr) return "";
        return ReadAsString(pos - ReaderPosition() + 1);
    }
    std::string GetLineAndPushOffSet() {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    void Clear() { reader_offset_ = writer_offset_ = 0; }
    
private:
    std::vector<char> buffer_;
    size_t reader_offset_;
    size_t writer_offset_;
};