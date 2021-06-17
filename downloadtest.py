def AssetDownload(downloadPath, ProgressBar, downloadProgress, ProgressLabel, size, Asset=0, chunkSize=1024):
        startTime = time.time()
        size = int(size)
        MBFACTOR = float(1 << 20)
        try:downloadURL = get(Version.json()["assets"][int(Asset)]["browser_download_url"])
        except Exception as e:messagebox.showerror("ERR_UNABLE_TO_CONNECT","An error occured while trying to connect to the GitHub servers. Please check your internet connection and firewall settings.\n\nError details: {}".format(e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: GitHub server connection failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
        else:
            try:
                try:os.remove(downloadPath)
                except:pass
                print("Starting downloading")
                ProgressBar.configure(maximum=size/1024*100)
                downloadProgress.set(0)
                downloadedSize = 0
                with open(downloadPath, mode='wb') as file:
                    for chunk in downloadURL.iter_content(chunk_size=chunkSize):
                        file.write(chunk)
                        """downloadedSize = downloadedSize + len(chunk)
                        downloadProgress.set(int(downloadProgress.get())*100)
                        format3 = int(size)/MBFACTOR
                        if int(int(downloadedSize)*(int(100/size))) > 10:
                            format2 = str(int(downloadedSize)*(int(100/size)))[:5]
                        elif not int(int(downloadedSize)*(int(100/size))) == 0:
                            format2 = "0" + str(int(downloadedSize)*(int(100/size)))[:5]
                        else:
                            format2 = str(int(downloadedSize)*(int(100/size)))[:5]
                        format1 = ((int(size)-int(downloadedSize))/MBFACTOR)
                        ProgressLabel.configure(text="Download progress: {:.1f} ({}%) MB out of {:.1f} MB downloaded".format(format1, format2, format3))"""
            except Exception as e:messagebox.showerror("ERR_DESTINATION_ACCESS_DENIED","An error occured while trying to write downloaded data to '{}' path. Please try again; if problem persists, try to run the program as administrator or change the download path.\n\nError details: {}".format(downloadPath,e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: File write operation failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
            else:ProgressLabel.configure(text="Download progress:");downloadProgress.set(0);finishTime = time.time();messagebox.showinfo("Download complete","Downloading '{}' file from 'github.com' completed sucsessfully. File has been saved to '{}'.\n\nDownload time: {}\nDownload Speed: {} MB/s\nFile size: {:.2f} MB".format(str(Version.json()["assets"][0]["name"]),("C:/Users/{}/Downloads/{}".format(getuser(), Version.json()["assets"][0]["name"])),str(finishTime-startTime)[:4]+" "+"Seconds",str(int(size) / MBFACTOR / float(str(finishTime-startTime)[:4]))[:4],int(size) / MBFACTOR))