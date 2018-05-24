﻿using CoreNFC;
using Foundation;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Bit.iOS
{
    public class NFCReaderDelegate : NFCNdefReaderSessionDelegate
    {
        private Regex _otpPattern = new Regex("^.*?([cbdefghijklnrtuv]{32,64})$");
        private Action<bool, string> _callback;

        public NFCReaderDelegate(Action<bool, string> callback)
        {
            _callback = callback;
        }

        public override void DidDetect(NFCNdefReaderSession session, NFCNdefMessage[] messages)
        {
            var results = new List<string>();
            foreach(var message in messages)
            {
                foreach(var record in message.Records)
                {
                    try
                    {
                        results.Add(new NSString(record.Payload, NSStringEncoding.UTF8));
                    }
                    catch { }
                }
            }

            foreach(var result in results)
            {
                Debug.WriteLine("READ TAG: " + result);
                if(_otpPattern.IsMatch(result))
                {
                    Debug.WriteLine("TAG IS MATCH: " + result);
                    _callback.Invoke(true, result);
                    return;
                }
            }

            _callback.Invoke(false, "No tags were read.");
        }

        public override void DidInvalidate(NFCNdefReaderSession session, NSError error)
        {
            _callback.Invoke(false, error?.LocalizedDescription);
        }
    }
}
