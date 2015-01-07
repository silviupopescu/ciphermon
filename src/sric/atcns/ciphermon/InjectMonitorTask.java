package sric.atcns.ciphermon;

import android.os.AsyncTask;
import android.util.Log;

public class InjectMonitorTask extends AsyncTask<String, Void, Void> {

	@Override
	protected Void doInBackground(String... apps) {
		int count = apps.length;
		for (int i = 0; i < count; i++)
			Log.d("InjectMonitorTask", "Injecting monitor hook into " + apps[i]);
			// TODO: call native method that performs the injection into zygote and waits until
			// zygote forks into the newly installed app
		return null;
	}

}
