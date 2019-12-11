# MyIDM_MP3
Bắt gói tin HTTP và phân tích thành phần để tìm link mp3 và tải về local
 1)  Chạy ứng dụng:
    chạy file WinPcap_Demo.cpp
 2) Nội dung khai thác:
  Gốm 2 phần chính:
   - Sử dụng winpcap để bắt gói tin
   - Sử dụng winsock để tạo socket gửi request và tải về file mp3 (blocking và non-blocking)
 3) Requirement:
  - properties => linker => add dependencies => thêm wpcap.lib,ws2_32.lib, Packet.lib => OK=> Apply
  - properties => C/C++ => Preprocessor => Preprocessor Definitions 
   => bổ sung: WIN32, WPCAP,HAVE_REMOTE,_DEBUG,_CONSOLE,_CRT_SECURE_NO_WARNINGS =>OK=> Apply
