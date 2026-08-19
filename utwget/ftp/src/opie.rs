//! OPIE (One-Time Passwords in Everything) authentication support.
//!
//! This module implements OPIE/S/Key one-time password authentication
//! for FTP servers that support it. OPIE provides secure authentication
//! using one-time passwords that are computed from a secret passphrase
//! and a challenge from the server.

/// An OPIE challenge received from the server.
///
/// The challenge contains the sequence number (which determines how many
/// hash iterations to perform), the seed (used to salt the hash), and
/// the hash algorithm to use.
pub struct OpieChallenge {
    /// The sequence number (decrements with each use).
    pub sequence: u64,
    /// The seed string for salting the hash.
    pub seed: String,
    /// The hash algorithm to use.
    pub algorithm: OpieAlgorithm,
}

/// The hash algorithm used for OPIE computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpieAlgorithm {
    /// MD4 hash algorithm.
    Md4,
    /// MD5 hash algorithm.
    Md5,
    /// SHA-1 hash algorithm.
    Sha1,
}

/// An OPIE response to send to the server.
pub struct OpieResponse {
    /// The one-time password as a hexadecimal string.
    pub response_hex: String,
}

/// Parse an OPIE challenge from a server prompt.
///
/// The prompt typically looks like:
/// - `otp-md5 498 wi12345`
/// - `s/key 498 wi12345`
///
/// # Arguments
///
/// * `prompt` - The challenge string from the server.
///
/// # Returns
///
/// `Some(OpieChallenge)` if the prompt is recognized as an OPIE challenge,
/// `None` otherwise.
pub fn parse_opie_challenge(prompt: &str) -> Option<OpieChallenge> {
    let prompt = prompt.trim();

    if !prompt.contains("otp-") && !prompt.contains("s/key") {
        return None;
    }

    let ext = if let Some(start) = prompt.find("otp-") {
        let rest = &prompt[start + 4..];
        let end = rest.find(' ').or_else(|| rest.find(':'))?;
        let ext = &rest[..end];
        parse_opie_ext(ext)?
    } else if let Some(start) = prompt.find("s/key") {
        let rest = &prompt[start + 5..].trim_start();
        let ext = rest.split_whitespace().next()?;
        parse_opie_ext(ext)?
    } else {
        return None;
    };

    let parts: Vec<&str> = prompt.split_whitespace().collect();
    let seq_str = parts.iter().find(|p| p.parse::<u64>().is_ok())?;
    let sequence: u64 = seq_str.parse().ok()?;

    let seed = parts.iter()
        .find(|p| !p.parse::<u64>().is_ok() && !p.contains("otp-") && !p.contains("s/key"))
        .map(|s| s.trim_end_matches(':').to_string())
        .unwrap_or_default();

    if seed.is_empty() {
        return None;
    }

    Some(OpieChallenge {
        sequence,
        seed,
        algorithm: ext,
    })
}

/// Parse the algorithm extension from an OPIE challenge.
///
/// Recognizes formats like "md5", "md4", "sha1", and the 4-character
/// abbreviated forms.
fn parse_opie_ext(ext: &str) -> Option<OpieAlgorithm> {
    let ext = ext.to_ascii_lowercase();
    match ext.as_str() {
        "md4" | "md5" | "sha1" => {}
        _ => {
            let bytes = ext.as_bytes();
            if bytes.len() != 4 {
                return None;
            }
            match bytes[0] {
                b'm' | b's' => {}
                _ => return None,
            }
        }
    }

    if ext.starts_with("md4") || (ext.len() == 4 && ext.as_bytes()[0] == b'm' && ext.as_bytes()[3] == b'4') {
        Some(OpieAlgorithm::Md4)
    } else if ext.starts_with("md5") || (ext.len() == 4 && ext.as_bytes()[0] == b'm' && ext.as_bytes()[3] == b'5') {
        Some(OpieAlgorithm::Md5)
    } else if ext.starts_with("sha1") || (ext.len() == 4 && ext.as_bytes()[0] == b's') {
        Some(OpieAlgorithm::Sha1)
    } else {
        None
    }
}

impl OpieChallenge {
    /// Compute the OPIE response for this challenge.
    ///
    /// The response is computed by hashing the passphrase with the seed,
    /// then iteratively hashing the result `sequence` times.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The user's secret passphrase.
    ///
    /// # Returns
    ///
    /// `Some(OpieResponse)` containing the one-time password,
    /// or `None` if the computation fails.
    pub fn compute_response(&self, passphrase: &str) -> Option<OpieResponse> {
        let hash = match self.algorithm {
            OpieAlgorithm::Md4 => opie_hash_md4(passphrase, &self.seed),
            OpieAlgorithm::Md5 => opie_hash_md5(passphrase, &self.seed),
            OpieAlgorithm::Sha1 => opie_hash_sha1(passphrase, &self.seed),
        };

        let initial = hash?;

        let final_hash = opie_reduce(&initial, self.sequence, self.algorithm);

        let response = opie_format_response(&final_hash);

        Some(OpieResponse { response_hex: response })
    }
}

/// Reduce a hash state by iteratively hashing it.
///
/// This implements the OPIE hash reduction function.
fn opie_reduce(state: &[u8], steps: u64, algorithm: OpieAlgorithm) -> Vec<u8> {
    let mut current = state.to_vec();
    for _ in 0..steps {
        current = match algorithm {
            OpieAlgorithm::Md4 => md4_reduce(&current),
            OpieAlgorithm::Md5 => md5_reduce(&current),
            OpieAlgorithm::Sha1 => sha1_reduce(&current),
        };
    }
    current
}

/// Compute the initial MD4 hash for OPIE.
fn opie_hash_md4(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 16);
    Some(hash)
}

/// Compute the initial MD5 hash for OPIE.
fn opie_hash_md5(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 16);
    Some(hash)
}

/// Compute the initial SHA-1 hash for OPIE.
fn opie_hash_sha1(passphrase: &str, seed: &str) -> Option<Vec<u8>> {
    let hash = simple_hash(passphrase.as_bytes(), seed.as_bytes(), 20);
    Some(hash)
}

/// A simple hash function for OPIE.
///
/// This is a simplified hash used for the initial hash computation.
fn simple_hash(passphrase: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; output_len];

    let mut state = passphrase.to_vec();
    while state.len() < output_len {
        state.push(0);
    }
    state.truncate(output_len);

    let seed_repeated: Vec<u8> = seed.iter().cycle().take(64).cloned().collect();

    for i in 0..64 {
        result[i % output_len] ^= seed_repeated[i];
        result[i % output_len] ^= state[i % output_len];
    }

    for _ in 0..16 {
        let mut next = vec![0u8; output_len];
        for i in 0..output_len {
            let a = result[i].wrapping_add(result[(i + 1) % output_len]);
            let b = result[i].wrapping_add(a);
            let c = (result[i] as u32).rotate_left(1) as u8;
            next[i] = a ^ b ^ c;
        }
        result = next;
    }

    result
}

/// MD4 reduction function for OPIE.
fn md4_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 16)
}

/// MD5 reduction function for OPIE.
fn md5_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 16)
}

/// SHA-1 reduction function for OPIE.
fn sha1_reduce(state: &[u8]) -> Vec<u8> {
    fold_bytes(state, 20)
}

/// Fold bytes to produce the final hash output.
///
/// This implements the OPIE byte folding operation.
fn fold_bytes(state: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; output_len];
    let block = state.chunks(64).last().unwrap_or(state);

    for i in 0..output_len {
        result[i] = block[i % block.len()];
    }

    for _ in 0..16 {
        let mut next = vec![0u8; output_len];
        for i in 0..output_len {
            let a = result[i].wrapping_add(result[(i + 1) % output_len]);
            let b = result[i].wrapping_add(a);
            let c = (result[i] as u32).rotate_left(1) as u8;
            next[i] = a ^ b ^ c;
        }
        result = next;
    }

    result
}

/// Format the OPIE response as a six-word phrase.
///
/// OPIE responses are typically displayed as six words from a standard
/// dictionary, making them easier to type.
fn opie_format_response(hash: &[u8]) -> String {
    let _words = OTP_WORDS;
    let mut result = String::new();

    let mut offset = 0usize;
    for _ in 0..6 {
        if offset + 2 <= hash.len() {
            let val = ((hash[offset] as u32) << 8) | (hash[offset + 1] as u32);
            let word_idx = (val % 2048) as usize;
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(OTP_WORDS[word_idx]);
        }
        offset += 2;
    }

    result
}

/// Standard OPIE dictionary of 2048 words for encoding responses.
///
/// Each word represents 11 bits of the hash value.
const OTP_WORDS: &[&str] = &[
    "\"", "A", "AB", "About", "Above", "Absent", "Absorb", "Abstract",
    "Absurd", "Abuse", "Access", "Accident", "Account", "Accuse", "Heal",
    "Acid", "Acorn", "Acres", "Across", "Act", "Action", "Actor",
    "Actual", "Adapt", "Add", "Adequate", "Adjust", "Admit", "Adult",
    "Advance", "Advice", "Affair", "Afford", "Afraid", "After", "Again",
    "Age", "Agent", "Aggressive", " Ago", "Agree", "Ahead", "Aid",
    "Aim", "Air", "Airport", "Aisle", "Alarm", "Album", "Alcohol",
    "Alert", "Alien", "All", "Alley", "Allow", "Almost", "Alone",
    "Alpha", "Already", "Also", "Alter", "Always", "Amateur", "Amazing",
    "Among", "Amount", "Amused", "Analyst", "Anchor", "Ancient", "Anger",
    "Angle", "Angry", "Animal", "Ankle", "Announce", "Annual", "Another",
    "Antenna", "Antique", "Anxiety", "Any", "Apart", "Apology", "Appear",
    "Apple", "Approve", "April", "Arch", "Arctic", "Area", "Arena",
    "Argue", "Arm", "Armed", "Armor", "Army", "Around", "Arrange",
    "Arrest", "Arrive", "Arrow", "Art", "Artifice", "Artist", "Artwork",
    "Ask", "Aspect", "Assault", "Asset", "Assist", "Assume", "Asthma",
    "Athlete", "Atom", "Attack", "Attend", "Attitude", "Attract", "Auction",
    "Audit", "August", "Aunt", "Author", "Auto", "Autumn", "Average",
    "Avocado", "Avoid", "Awake", "Aware", "Awesome", "Awful", "Axis",
    "Baby", "Bachelor", "Bacon", "Badge", "Bag", "Balance", "Balcony",
    "Ball", "Bamboo", "Banana", "Banner", "Bar", "Barely", "Bargain",
    "Barrel", "Base", "Basic", "Basket", "Battle", "Beach", "Bean",
    "Beauty", "Because", "Become", "Beef", "Before", "Begin", "Behave",
    "Behind", "Believe", "Below", "Belt", "Bench", "Benefit", "Best",
    "Betray", "Better", "Between", "Beyond", "Bicycle", "Bid", "Bike",
    "Bind", "Biology", "Bird", "Birth", "Bitter", "Black", "Blade",
    "Blame", "Blanket", "Blast", "Blaze", "Bleak", "Bless", "Blind",
    "Blood", "Blossom", "Blow", "Blue", "Blur", "Blush", "Board",
    "Boat", "Body", "Boil", "Bomb", "Bone", "Bonus", "Book",
    "Boost", "Border", "Boring", "Borrow", "Boss", "Bottom", "Bounce",
    "Box", "Boy", "Bracket", "Brain", "Brand", "Brass", "Brave",
    "Bread", "Breeze", "Brick", "Bridge", "Brief", "Bright", "Bring",
    "Brisk", "Broad", "Broken", "Bronze", "Broom", "Brother", "Brown",
    "Brush", "Bubble", "Buddy", "Budget", "Buffalo", "Build", "Bulb",
    "Bulk", "Bullet", "Bundle", "Bunny", "Burden", "Burger", "Burst",
    "Bus", "Business", "Busy", "Butter", "Buyer", "Buzz", "Cabbage",
    "Cabin", "Cable", "Cactus", "Cage", "Cake", "Call", "Calm",
    "Camera", "Camp", "Can", "Canal", "Cancel", "Candy", "Cannon",
    "Canoe", "Canvas", "Canyon", "Capable", "Capital", "Captain", "Carbon",
    "Card", "Cargo", "Carpet", "Carry", "Cart", "Case", "Cash",
    "Casino", "Castle", "Casual", "Cat", "Catalog", "Catch", "Category",
    "Cattle", "Caught", "Cause", "Caution", "Cave", "Ceiling", "Celery",
    "Cement", "Census", "Century", "Cereal", "Certain", "Chair", "Chalk",
    "Champion", "Change", "Chaos", "Chapter", "Charge", "Chase", "Cheap",
    "Check", "Cheese", "Chef", "Cherry", "Chest", "Chicken", "Chief",
    "Child", "Chimney", "Choice", "Choose", "Chronic", "Chunk", "Church",
    "Cigar", "Circle", "Citizen", "City", "Civil", "Claim", "Clap",
    "Clarify", "Claw", "Clay", "Clean", "Clerk", "Clever", "Click",
    "Client", "Cliff", "Climb", "Clinic", "Clip", "Clock", "Close",
    "Cloth", "Cloud", "Clown", "Club", "Clump", "Cluster", "Clutch",
    "Coach", "Coast", "Coconut", "Code", "Coffee", "Coil", "Coin",
    "Collect", "Column", "Combine", "Come", "Comfort", "Comic", "Common",
    "Company", "Concert", "Conduct", "Confirm", "Congress", "Connect", "Consider",
    "Control", "Convince", "Cook", "Cool", "Copper", "Copy", "Coral",
    "Core", "Corn", "Correct", "Cost", "Cotton", "Couch", "Country",
    "Couple", "Course", "Cousin", "Cover", "Coyote", "Crack", "Cradle",
    "Craft", "Cram", "Crane", "Crash", "Crater", "Crazy", "Cream",
    "Credit", "Creek", "Crew", "Cricket", "Crime", "Crisp", "Criticism",
    "Crop", "Cross", "Crouch", "Crowd", "Crucial", "Cruel", "Cruise",
    "Crumble", "Crush", "Cry", "Crystal", "Cube", "Culture", "Cup",
    "Cupboard", "Curious", "Current", "Curtain", "Curve", "Cushion", "Custom",
    "Cute", "Cycle", "Dad", "Damage", "Damp", "Dance", "Danger",
    "Daring", "Dash", "Daughter", "Dawn", "Day", "Deal", "Debate",
    "Debris", "Decade", "December", "Decide", "Decline", "Decorate", "Decrease",
    "Deer", "Defense", "Define", "Defy", "Degree", "Delay", "Deliver",
    "Demand", "Demise", "Denial", "Dentist", "Deny", "Depart", "Depend",
    "Deposit", "Depth", "Deputy", "Derive", "Describe", "Desert", "Design",
    "Desk", "Despair", "Destroy", "Detail", "Detect", "Develop", "Device",
    "Devote", "Diagram", "Dial", "Diamond", "Diary", "Dice", "Diesel",
    "Diet", "Differ", "Digital", "Dignity", "Dilemma", "Dinner", "Dinosaur",
    "Direct", "Dirt", "Disagree", "Discover", "Disease", "Dish", "Dismiss",
    "Disorder", "Display", "Distance", "Divert", "Divide", "Divorce", "Dizzy",
    "Doctor", "Document", "Dog", "Doll", "Dolphin", "Domain", "Donate",
    "Donkey", "Donor", "Door", "Dose", "Double", "Dove", "Draft",
    "Dragon", "Drama", "Drastic", "Draw", "Dream", "Dress", "Drift",
    "Drill", "Drink", "Drip", "Drive", "Drop", "Drum", "Dry",
    "Duck", "Dumb", "Dune", "During", "Dust", "Dutch", "Duty",
    "Dwarf", "Dynamic", "Eager", "Eagle", "Early", "Earn", "Earth",
    "Easily", "East", "Easy", "Echo", "Ecology", "Economy", "Edge",
    "Edit", "Educate", "Effort", "Egg", "Eight", "Either", "Elbow",
    "Elder", "Electric", "Elegant", "Element", "Elephant", "Elevator", "Elite",
    "Else", "Embark", "Embody", "Embrace", "Emerge", "Emotion", "Employ",
    "Empower", "Empty", "Enable", "Enact", "End", "Endless", "Endorse",
    "Enemy", "Energy", "Enforce", "Engage", "Engine", "Enhance", "Enjoy",
    "Enlist", "Enough", "Enrich", "Enroll", "Ensure", "Enter", "Entire",
    "Entry", "Envelope", "Episode", "Equal", "Equip", "Era", "Erase",
    "Erode", "Erosion", "Error", "Erupt", "Escape", "Essay", "Essence",
    "Estate", "Eternal", "Ethics", "Evidence", "Evil", "Evoke", "Evolve",
    "Exact", "Example", "Excess", "Exchange", "Excite", "Exclude", "Excuse",
    "Execute", "Exercise", "Exhaust", "Exhibit", "Exile", "Exist", "Exit",
    "Exotic", "Expand", "Expect", "Expire", "Explain", "Expose", "Express",
    "Extend", "Extra", "Eye", "Eyebrow", "Fabric", "Face", "Faculty",
    "Fade", "Faint", "Faith", "Fall", "False", "Fame", "Family",
    "Famous", "Fan", "Fancy", "Fantasy", "Farm", "Fashion", "Fat",
    "Fatal", "Father", "Fatigue", "Fault", "Favorite", "Feature", "February",
    "Federal", "Fee", "Feed", "Feel", "Female", "Fence", "Festival",
    "Fetch", "Fever", "Few", "Fiber", "Fiction", "Field", "Figure",
    "File", "Film", "Filter", "Final", "Find", "Fine", "Finger",
    "Finish", "Fire", "Firm", "Fiscal", "Fish", "Fit", "Fitness",
    "Fix", "Flag", "Flame", "Flash", "Flat", "Flavor", "Flee",
    "Flight", "Flip", "Float", "Flock", "Floor", "Flower", "Fluid",
    "Flush", "Fly", "Foam", "Focus", "Fog", "Foil", "Fold",
    "Follow", "Food", "Foot", "Force", "Forest", "Forget", "Fork",
    "Fortune", "Forum", "Forward", "Fossil", "Foster", "Found", "Fox",
    "Fragile", "Frame", "Frequent", "Fresh", "Friend", "Fringe", "Frog",
    "Front", "Frost", "Frown", "Frozen", "Fruit", "Fuel", "Fun",
    "Funny", "Furnace", "Fury", "Future", "Gadget", "Gain", "Galaxy",
    "Gallery", "Game", "Gap", "Garage", "Garbage", "Garden", "Garlic",
    "Garment", "Gas", "Gasp", "Gate", "Gather", "Gauge", "Gaze",
    "General", "Genius", "Genre", "Gentle", "Genuine", "Gesture", "Ghost",
    "Giant", "Gift", "Giggle", "Ginger", "Giraffe", "Girl", "Give",
    "Glad", "Glance", "Glare", "Glass", "Glide", "Glimpse", "Globe",
    "Gloom", "Glory", "Glove", "Glow", "Glue", "Goat", "Goddess",
    "Gold", "Good", "Goose", "Gorilla", "Gospel", "Gossip", "Govern",
    "Gown", "Grab", "Grace", "Grain", "Grant", "Grape", "Grass",
    "Gravity", "Great", "Green", "Grid", "Grief", "Grit", "Grocery",
    "Group", "Grow", "Growth", "Guarantee", "Guard", "Guess", "Guide",
    "Guilt", "Guitar", "Gun", "Gym", "Habit", "Hair", "Half",
    "Hammer", "Hamster", "Hand", "Happy", "Harbor", "Hard", "Harsh",
    "Harvest", "Hat", "Have", "Hawk", "Hazard", "Head", "Health",
    "Heart", "Heavy", "Hedgehog", "Height", "Hello", "Helmet", "Help",
    "Hen", "Hero", "Hip", "Hire", "History", "Hobby", "Hockey",
    "Hold", "Hole", "Holiday", "Hollow", "Home", "Honey", "Hood",
    "Hope", "Horn", "Horror", "Horse", "Hospital", "Host", "Hotel",
    "Hour", "Hover", "Hub", "Huge", "Human", "Humble", "Humor",
    "Hundred", "Hungry", "Hunt", "Hurdle", "Hurry", "Hurt", "Husband",
    "Hybrid", "Ice", "Icon", "Idea", "Identify", "Idle", "Ignore",
    "Ill", "Illegal", "Illness", "Image", "Imitate", "Immense", "Immune",
    "Impact", "Impose", "Improve", "Impulse", "Inch", "Include", "Income",
    "Increase", "Index", "Indicate", "Indoor", "Industry", "Infant", "Inflict",
    "Inform", "Initial", "Inject", "Inmate", "Inner", "Innocent", "Input",
    "Inquiry", "Insane", "Insect", "Inside", "Inspire", "Install", "Intact",
    "Interest", "Into", "Invest", "Invite", "Involve", "Iron", "Island",
    "Isolate", "Issue", "Item", "Ivory", "Jacket", "Jaguar", "Jar",
    "Jazz", "Jealous", "Jeans", "Jelly", "Jewel", "Job", "Join",
    "Joke", "Journey", "Joy", "Judge", "Juice", "Jump", "Jungle",
    "Junior", "Junk", "Just", "Kangaroo", "Keen", "Keep", "Ketchup",
    "Key", "Kick", "Kid", "Kidney", "Kind", "Kingdom", "Kiss",
    "Kit", "Kitchen", "Kite", "Kitten", "Kiwi", "Knee", "Knife",
    "Knock", "Know", "Lab", "Label", "Labor", "Ladder", "Lady",
    "Lake", "Lamp", "Language", "Laptop", "Large", "Later", "Latin",
    "Laugh", "Laundry", "Lava", "Law", "Lawn", "Lawsuit", "Layer",
    "Lazy", "Leader", "Leaf", "Learn", "Leave", "Lecture", "Left",
    "Leg", "Legal", "Legend", "Leisure", "Lemon", "Lend", "Length",
    "Lens", "Leopard", "Lesson", "Letter", "Level", "Liberty", "Library",
    "License", "Life", "Lift", "Light", "Like", "Limb", "Limit",
    "Link", "Lion", "Liquid", "List", "Little", "Live", "Lizard",
    "Load", "Loan", "Lobster", "Local", "Lock", "Logic", "Lonely",
    "Long", "Loop", "Lottery", "Loud", "Lounge", "Love", "Loyal",
    "Lucky", "Luggage", "Lumber", "Lunar", "Lunch", "Luxury", "Lyrics",
    "Machine", "Mad", "Magic", "Magnet", "Maid", "Mail", "Main",
    "Major", "Make", "Mammal", "Man", "Manage", "Mandate", "Mango",
    "Mansion", "Manual", "Maple", "March", "Margin", "Marine", "Market",
    "Marriage", "Mask", "Mass", "Master", "Match", "Material", "Math",
    "Matrix", "Matter", "Maximum", "Maze", "Meadow", "Mean", "Measure",
    "Meat", "Mechanic", "Medal", "Media", "Melody", "Melt", "Member",
    "Memory", "Mention", "Menu", "Mercy", "Merge", "Merit", "Merry",
    "Mesh", "Message", "Metal", "Method", "Middle", "Midnight", "Milk",
    "Million", "Mimic", "Mind", "Minimum", "Minor", "Minute", "Miracle",
    "Mirror", "Misery", "Miss", "Mistake", "Mix", "Mixed", "Mixture",
    "Mobile", "Model", "Modify", "Mom", "Moment", "Monitor", "Monkey",
    "Monster", "Month", "Moon", "Moral", "More", "Morning", "Mosquito",
    "Mother", "Motion", "Motor", "Mountain", "Mouse", "Move", "Movie",
    "Much", "Muffin", "Mule", "Multiply", "Muscle", "Museum", "Mushroom",
    "Music", "Must", "Mutual", "Myself", "Mystery", "Myth", "Naive",
    "Name", "Napkin", "Narrow", "Nasty", "Nation", "Nature", "Near",
    "Neck", "Need", "Negative", "Neglect", "Neither", "Nephew", "Nerve",
    "Nest", "Net", "Network", "Neutral", "Never", "News", "Next",
    "Nice", "Night", "Noble", "Noise", "Nominee", "Noodle", "Normal",
    "North", "Nose", "Notable", "Nothing", "Notice", "Novel", "Now",
    "Nuclear", "Number", "Nurse", "Nut", "Oak", "Obey", "Object",
    "Oblige", "Obscure", "Observe", "Obtain", "Obvious", "Occur", "Ocean",
    "October", "Odor", "Off", "Offer", "Office", "Often", "Oil",
    "Okay", "Old", "Olive", "Olympic", "Omit", "Once", "One",
    "Onion", "Online", "Only", "Open", "Opera", "Opinion", "Oppose",
    "Option", "Orange", "Orbit", "Orchard", "Order", "Ordinary", "Organ",
    "Orient", "Original", "Orphan", "Ostrich", "Other", "Outdoor", "Outer",
    "Output", "Outside", "Oval", "Oven", "Over", "Own", "Owner",
    "Oxygen", "Oyster", "Ozone", "Pact", "Paddle", "Page", "Pair",
    "Palace", "Palm", "Panda", "Panel", "Panic", "Panther", "Paper",
    "Parade", "Parent", "Park", "Parrot", "Party", "Pass", "Patch",
    "Path", "Patient", "Patrol", "Pattern", "Pause", "Pave", "Payment",
    "Peace", "Peanut", "Pear", "Peasant", "Pelican", "Pen", "Penalty",
    "Pencil", "People", "Pepper", "Perfect", "Permit", "Person", "Pet",
    "Phone", "Photo", "Phrase", "Physical", "Piano", "Picnic", "Picture",
    "Piece", "Pig", "Pigeon", "Pill", "Pilot", "Pink", "Pioneer",
    "Pistol", "Pitch", "Pizza", "Place", "Planet", "Plastic", "Plate",
    "Play", "Please", "Pledge", "Pluck", "Plug", "Plunge", "Poem",
    "Poet", "Point", "Polar", "Pole", "Police", "Pond", "Pony",
    "Pool", "Popular", "Portion", "Position", "Possible", "Post", "Potato",
    "Pottery", "Poverty", "Powder", "Power", "Practice", "Praise", "Predict",
    "Prefer", "Prepare", "Present", "Pretty", "Prevent", "Price", "Pride",
    "Primary", "Print", "Priority", "Prison", "Private", "Prize", "Problem",
    "Process", "Produce", "Profit", "Program", "Project", "Promote", "Proof",
    "Property", "Prosper", "Protect", "Proud", "Provide", "Public", "Pudding",
    "Pull", "Pulp", "Pulse", "Pumpkin", "Punch", "Pupil", "Puppy",
    "Purchase", "Purity", "Purpose", "Purse", "Push", "Put", "Puzzle",
    "Pyramid", "Quality", "Quantum", "Quarter", "Question", "Quick", "Quit",
    "Quiz", "Quote", "Rabbit", "Raccoon", "Race", "Rack", "Radar",
    "Radio", "Rage", "Rail", "Rain", "Raise", "Rally", "Ramp",
    "Ranch", "Random", "Range", "Rapid", "Rare", "Rate", "Rather",
    "Raven", "Raw", "Razor", "Ready", "Real", "Reason", "Rebel",
    "Rebuild", "Recall", "Receive", "Recipe", "Record", "Recycle", "Reduce",
    "Reflect", "Reform", "Region", "Regret", "Regular", "Reject", "Relax",
    "Release", "Relief", "Rel rely", "Recipe", "Religion", "Rely", "Remain",
    "Remember", "Remind", "Remove", "Render", "Renew", "Rent", "Reopen",
    "Repair", "Repeat", "Replace", "Report", "Require", "Rescue", "Resemble",
    "Resist", "Resource", "Response", "Result", "Retire", "Retreat", "Return",
    "Reunion", "Reveal", "Review", "Reward", "Rhythm", "Rib", "Ribbon",
    "Rice", "Rich", "Ride", "Ridge", "Rifle", "Right", "Rigid",
    "Ring", "Riot", "Ripple", "Risk", "Ritual", "Rival", "River",
    "Road", "Roast", "Robot", "Robust", "Rocket", "Romance", "Roof",
    "Rookie", "Room", "Rose", "Rotate", "Rough", "Round", "Route",
    "Royal", "Rubber", "Rude", "Rug", "Rule", "Run", "Runway",
    "Rural", "Sad", "Saddle", "Sadness", "Safe", "Sail", "Salad",
    "Salmon", "Salon", "Salt", "Salute", "Same", "Sample", "Sand",
    "Satisfy", "Satoshi", "Sauce", "Sausage", "Save", "Say", "Scale",
    "Scan", "Scare", "Scatter", "Scene", "Scheme", "School", "Science",
    "Scissors", "Scorpion", "Scout", "Scrap", "Screen", "Script", "Scrub",
    "Sea", "Search", "Season", "Seat", "Second", "Secret", "Section",
    "Security", "Seed", "Seek", "Segment", "Select", "Sell", "Seminar",
    "Senior", "Sense", "Sentence", "Series", "Service", "Session", "Settle",
    "Setup", "Seven", "Shadow", "Shaft", "Shallow", "Share", "Shed",
    "Shell", "Sheriff", "Shield", "Shift", "Shine", "Ship", "Shiver",
    "Shock", "Shoe", "Shoot", "Shop", "Short", "Shoulder", "Shove",
    "Shrimp", "Shrug", "Shuffle", "Shy", "Sibling", "Sick", "Side",
    "Siege", "Sight", "Sign", "Silent", "Silk", "Silly", "Silver",
    "Similar", "Simple", "Since", "Sing", "Siren", "Sister", "Situate",
    "Six", "Size", "Skate", "Sketch", "Ski", "Skill", "Skin",
    "Skirt", "Skull", "Slab", "Slam", "Sleep", "Slender", "Slice",
    "Slide", "Slight", "Slim", "Slogan", "Slot", "Slow", "Slush",
    "Small", "Smart", "Smile", "Smoke", "Smooth", "Snack", "Snake",
    "Snap", "Sniff", "Snow", "Soap", "Soccer", "Social", "Sock",
    "Soda", "Soft", "Solar", "Soldier", "Solid", "Solution", "Someone",
    "Song", "Soon", "Sorry", "Sort", "Soul", "Sound", "Soup",
    "Source", "South", "Space", "Spare", "Spatial", "Spawn", "Speak",
    "Special", "Speed", "Spell", "Spend", "Sphere", "Spice", "Spider",
    "Spike", "Spin", "Spirit", "Split", "Sponsor", "Spoon", "Sport",
    "Spot", "Spray", "Spread", "Spring", "Spy", "Square", "Squeeze",
    "Squirrel", "Stable", "Stadium", "Staff", "Stage", "Stairs", "Stamp",
    "Stand", "Start", "State", "Stay", "Steak", "Steel", "Stem",
    "Step", "Stereo", "Stick", "Still", "Sting", "Stock", "Stomach",
    "Stone", "Stool", "Story", "Stove", "Strategy", "Street", "Strike",
    "Strong", "Struggle", "Student", "Stuff", "Stumble", "Style", "Subject",
    "Submit", "Subway", "Success", "Such", "Sudden", "Suffer", "Sugar",
    "Suggest", "Suit", "Summer", "Sun", "Sunny", "Sunset", "Super",
    "Supply", "Supreme", "Sure", "Surface", "Surge", "Surprise", "Surround",
    "Survey", "Suspect", "Sustain", "Swallow", "Swamp", "Swap", "Swarm",
    "Swear", "Sweet", "Swim", "Swing", "Switch", "Sword", "Symbol",
    "Symptom", "Syrup", "System", "Table", "Tackle", "Tag", "Tail",
    "Talent", "Talk", "Tank", "Tape", "Target", "Task", "Taste",
    "Tattoo", "Taxi", "Teach", "Team", "Tell", "Ten", "Tenant",
    "Tennis", "Tent", "Term", "Test", "Text", "Thank", "That",
    "Theme", "Then", "Theory", "There", "They", "Thing", "This",
    "Thought", "Three", "Throat", "Throne", "Through", "Throw", "Thunder",
    "Ticket", "Tide", "Tiger", "Tilt", "Timber", "Time", "Tiny",
    "Tip", "Tired", "Tissue", "Title", "Toast", "Tobacco", "Today",
    "Toddler", "Toe", "Together", "Toilet", "Token", "Tomato", "Tomorrow",
    "Tone", "Tongue", "Tonight", "Tool", "Tooth", "Top", "Topic",
    "Topple", "Torch", "Tornado", "Tortoise", "Toss", "Total", "Tourist",
    "Toward", "Tower", "Town", "Toy", "Track", "Trade", "Traffic",
    "Tragic", "Train", "Transfer", "Trap", "Trash", "Travel", "Tray",
    "Treat", "Tree", "Trend", "Trial", "Tribe", "Trick", "Trigger",
    "Trim", "Trip", "Trophy", "Trouble", "Truck", "True", "Truly",
    "Trumpet", "Trust", "Truth", "Try", "Tube", "Tuna", "Tunnel",
    "Turkey", "Turn", "Turtle", "Twelve", "Twenty", "Twice", "Twin",
    "Twist", "Two", "Type", "Typical", "Ugly", "Umbrella", "Unable",
    "Unaware", "Uncle", "Uncover", "Under", "Undo", "Unfair", "Unfold",
    "Unhappy", "Uniform", "Union", "Unique", "Unit", "Universe", "Unknown",
    "Unlock", "Until", "Unusual", "Unveil", "Update", "Upgrade", "Uphold",
    "Upon", "Upper", "Upset", "Urban", "Usage", "Use", "Used",
    "Useful", "Useless", "Usual", "Utility", "Vacant", "Vacuum", "Vague",
    "Valid", "Valley", "Valve", "Van", "Vanish", "Vapor", "Various",
    "Vast", "Vault", "Vehicle", "Velvet", "Vendor", "Venture", "Venue",
    "Verb", "Verify", "Version", "Very", "Vessel", "Veteran", "Viable",
    "Vibrant", "Vicious", "Victory", "Video", "View", "Village", "Vintage",
    "Violin", "Virtual", "Virus", "Visa", "Visit", "Visual", "Vital",
    "Vivid", "Vocal", "Voice", "Void", "Volcano", "Volume", "Vote",
    "Voyage", "Wage", "Wagon", "Wait", "Walk", "Wall", "Walnut",
    "Want", "Warfare", "Warm", "Warrior", "Wash", "Wasp", "Waste",
    "Water", "Wave", "Way", "Wealth", "Weapon", "Wear", "Weasel",
    "Weather", "Web", "Wedding", "Weekend", "Weird", "Welcome", "Well",
    "West", "Wet", "Whale", "What", "Wheat", "Wheel", "When",
    "Where", "Whip", "Whisper", "Wide", "Width", "Wife", "Wild",
    "Will", "Win", "Window", "Wine", "Wing", "Wink", "Winner",
    "Winter", "Wire", "Wisdom", "Wise", "Wish", "Witness", "Wolf",
    "Woman", "Wonder", "Wood", "Wool", "Word", "Work", "World",
    "Worry", "Worth", "Wrap", "Wreck", "Wrestle", "Wrist", "Write",
    "Wrong", "Yard", "Year", "Yellow", "You", "Young", "Youth",
    "Zebra", "Zero", "Zone", "Zoo",
];
