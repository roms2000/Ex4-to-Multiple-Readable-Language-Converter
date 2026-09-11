//+------------------------------------------------------------------+
//| Decompiled from Super_Arrow_Indicator.ex4
//| Type: Indicator
//| Version: Unknown
//| Link: http://www.ebay.com/usr/forexforyou
//+------------------------------------------------------------------+
//| NOTE: EX4 is a compiled/encrypted format. This is a best-effort
//| reconstruction from surviving metadata/strings, not the original
//| source. Review and adapt before use.
//+------------------------------------------------------------------+

#property indicator_separate_window
#property indicator_buffers 1

double Buffer1[];

//+------------------------------------------------------------------+
//| Initialization function
//+------------------------------------------------------------------+
int init()
{
    SetIndexStyle(0, DRAW_LINE);
    SetIndexBuffer(0, Buffer1);
    SetIndexLabel(0, "Main Buffer");
    return(0);
}

//+------------------------------------------------------------------+
//| Deinitialization function
//+------------------------------------------------------------------+
int deinit()
{
    return(0);
}

//+------------------------------------------------------------------+
//| Main function
//+------------------------------------------------------------------+
int start()
{
    return(0);
}
