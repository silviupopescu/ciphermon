package sric.atcns.ciphermon;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootUpReceiver extends BroadcastReceiver {

	@Override
	public void onReceive(Context ctx, Intent intt) {
		Log.d("BootUpReceiver", "Started at boot.");
	}

}
