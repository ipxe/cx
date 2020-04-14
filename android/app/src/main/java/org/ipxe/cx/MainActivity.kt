package org.ipxe.cx

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.*
import org.ipxe.gen.*
import org.spongycastle.util.encoders.Hex

/**
 * Simple demonstration of Contact Identifier generation using fixed seed values. Intended for
 * demonstration purposes of the Generator algorithms only.
 *
 * Note: Reaching the iteration limit for a generator is not handled so if the user presses the
 * "Iterate" button 2048 times then the app will crash with an unhandled exception.
 */
class MainActivity : AppCompatActivity() {
    // FIXME: The state management here is quick and dirty for demo purposes only!
    private lateinit var gen: ContactIDGenerator
    private lateinit var contactIDListAdapter: ArrayAdapter<String>
    private val contactIDs = arrayListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val contactIDListView = findViewById<ListView>(R.id.cx_id_list_view)
        contactIDListAdapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_1, contactIDs
        )
        contactIDListView.adapter = contactIDListAdapter

        // See above FIXME
        // Start with Type 1 selected
        initGenerator(Type1)
        val radioGroup = findViewById<RadioGroup>(R.id.radio_cx_gen_type)
        radioGroup.check(radioGroup.findViewById<RadioButton>(R.id.radio_gen_type1).id)

        // Re-instantiate the generator when the user selects a generator type
        radioGroup.setOnCheckedChangeListener(
            RadioGroup.OnCheckedChangeListener { _, checkedId ->
                initGenerator(
                    when (checkedId) {
                        R.id.radio_gen_type1 -> Type1
                        R.id.radio_gen_type2 -> Type2
                        else -> TODO() // FIXME: Handle this properly
                    }
                )
            })

        // Generate and display a new Contact Identifier when the user presses the "Iterate" button
        // FIXME: No handling of reaching the iteration limit
        findViewById<Button>(R.id.button_cx_id_iterate).setOnClickListener() {
            val nextId = gen.iterate()
            val idStr = nextId.toString()
            Log.d("MAIN", "Generated ID: $idStr")
            contactIDs.add(idStr)
            contactIDListAdapter.notifyDataSetChanged()
        }

    }

    /**
     * Initialise [gen] to a new [ContactIDGenerator] and clear the list of Contact Identifiers.
     *
     * Note: Uses a **fixed seed** for each [GeneratorType] - this is for demo purposes only.
     */
    private fun initGenerator(type: GeneratorType) {
        gen = when (type) {
            Type1 -> ContactIDGenerator.ofType(
                type,
                Hex.decode("00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617")
            )
            Type2 -> ContactIDGenerator.Companion.ofType(
                type,
                Hex.decode(
                    """
                        00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617
                        18191A1B 1C1D1E1F 20212223 24252627 28292A2B 2C2D2E2F
                        """
                )
            )
        }
        contactIDs.clear()
        contactIDListAdapter.notifyDataSetChanged()
    }
}
