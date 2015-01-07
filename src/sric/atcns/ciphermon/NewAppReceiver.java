package sric.atcns.ciphermon;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class NewAppReceiver extends BroadcastReceiver {

	@Override
	public void onReceive(Context context, Intent intent) {
		String newAppName = intent.getData().getSchemeSpecificPart();
		Log.d("NewAppReceiver", "New application installed: " + newAppName);
		new InjectMonitorTask().execute(newAppName);
	}

}
