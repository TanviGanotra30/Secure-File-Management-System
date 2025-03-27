import os
import struct
import time
from stat import ST_CTIME, ST_MTIME, ST_SIZE
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter import messagebox, filedialog

MAX_PATH = 256
SIGNATURE = b"FILE_RECOVERY_SIG"

class FileHeader:
    def __init__(self):
        self.signature = SIGNATURE
        self.filename = b""
        self.size = 0
        self.created = 0
        self.modified = 0

    def pack(self):
        return struct.pack(f"16s{MAX_PATH}sqq", 
                         self.signature,
                         self.filename,
                         self.size,
                         int(self.created),
                         int(self.modified))

    @classmethod
    def unpack(cls, data):
        header = cls()
        (header.signature,
         header.filename,
         header.size,
         header.created,
         header.modified) = struct.unpack(f"16s{MAX_PATH}sqq", data)
        return header

class FileRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Recovery System")
        self.root.geometry("600x400")
        
        # Output window
        self.output_text = ScrolledText(root, wrap=WORD, width=70, height=20)
        self.output_text.pack(pady=10)
        self.output_text.config(state=DISABLED)
        
        # Buttons frame
        btn_frame = Frame(root)
        btn_frame.pack(pady=10)
        
        # Buttons
        Button(btn_frame, text="Backup File", command=self.backup_gui).pack(side=LEFT, padx=5)
        Button(btn_frame, text="Recover Files", command=self.recover_gui).pack(side=LEFT, padx=5)
        Button(btn_frame, text="Exit", command=root.quit).pack(side=LEFT, padx=5)
    
    def log_message(self, message):
        self.output_text.config(state=NORMAL)
        self.output_text.insert(END, message + "\n")
        self.output_text.config(state=DISABLED)
        self.output_text.see(END)
        self.root.update()
    
    def backup_gui(self):
        filename = filedialog.askopenfilename(title="Select file to backup")
        if filename:
            self.backup_file(filename)
    
    def recover_gui(self):
        drive_path = filedialog.askopenfilename(title="Select drive/file to scan")
        if drive_path:
            self.recover_files(drive_path)
    
    def recover_files(self, drive_path):
        try:
            with open(drive_path, 'rb') as drive:
                self.log_message("\nScanning for recoverable files...\n")
                
                output_dir = "recovered_files"
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                    self.log_message(f"Created recovery directory: {output_dir}")

                found_files = 0
                position = 0
                header_size = struct.calcsize(f"16s{MAX_PATH}sqq")
                
                while True:
                    drive.seek(position)
                    header_data = drive.read(header_size)
                    if not header_data:
                        break
                        
                    try:
                        header = FileHeader.unpack(header_data)
                    except struct.error:
                        position += 1
                        continue
                    
                    if header.signature == SIGNATURE:
                        filename = header.filename.decode('utf-8').strip('\x00')
                        msg = f"Found file: {filename} (Size: {header.size} bytes)"
                        self.log_message(msg)
                        
                        recovery_path = os.path.join(output_dir, filename)
                        file_data = drive.read(header.size)
                        
                        with open(recovery_path, 'wb') as recovered_file:
                            recovered_file.write(file_data)
                        
                        # Restore timestamps
                        os.utime(recovery_path, (header.created, header.modified))
                        found_files += 1
                        position += header_size + header.size
                    else:
                        position += 1

                self.log_message(f"\nRecovery complete. Found {found_files} files in directory '{output_dir}'")
                messagebox.showinfo("Success", f"Recovery complete! Found {found_files} files.")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))
    
    def backup_file(self, filename):
        try:
            file_stat = os.stat(filename)
            
            header = FileHeader()
            header.filename = os.path.basename(filename).encode('utf-8')
            header.size = file_stat[ST_SIZE]
            header.created = file_stat[ST_CTIME]
            header.modified = file_stat[ST_MTIME]
            
            with open(filename, 'rb') as src, open("backup.dat", 'ab') as backup:
                backup.write(header.pack())
                backup.write(src.read(header.size))
                
            self.log_message(f"Backup created for: {filename}")
            messagebox.showinfo("Success", f"Backup created for: {filename}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = FileRecoveryApp(root)
    root.mainloop()