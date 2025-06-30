#pragma description "Construct Classic LEVELBLOCK Binary Format"
#pragma endian little
#pragma name_style camelCase

import std.mem;

// A helper for the length-prefixed CString used throughout the file.
struct CString {
    u32 length;
    char value[length];
};

struct PyFunction {
        CString name;
        u32 param_count;
};

// Structure for Python-related script information found in some objects.
struct PythonInfo {
    u32 action_count;
    
    PyFunction actions[action_count];

    u32 condition_count;
    PyFunction conditions[condition_count];

    u32 expression_count;
    PyFunction expressions[expression_count];
};

// Represents a private variable definition for an object type.
struct PrivateVar {
    CString name;
    u32 type; // 0 for numeric, 1 for text
};

// Defines an Object Type (Sprite, etc.)
struct ObjectType {
    u32 type_id;
    CString name;
    u32 type_identifier;
    u8 is_global;
    u32 destroy_when; // Enum DisableShaderWhen
    u32 num_private_vars;
    PrivateVar private_vars[num_private_vars];
    u8 unknown_data[16];
    u8 has_python_info;
    if (has_python_info == 1) {
        PythonInfo python_info;
    }
} [[name("ObjectType")]];

// Defines a Movement behavior attached to an object type.
struct MovementType {
    u32 object_oid;
    u32 assoc_dll;
    u32 mov_index;
    CString aux_name;
    u32 mov_data_size;
    u8 mov_data[mov_data_size];
    u8 has_python_info;
    if (has_python_info == 1) {
        PythonInfo python_info;
    }
} [[name("MovementType")]];

// Defines a Trait (a grouping of objects).
struct Trait {
    CString name;
    u32 num_objects_in_trait;
    u32 trait_oids[num_objects_in_trait];
} [[name("Trait")]];

// Defines a Family (a group of similar object types).
struct Family {
    CString name;
    u32 num_children;
    u32 children_oids[num_children];
    u32 num_private_vars;
    PrivateVar private_vars[num_private_vars];
} [[name("Family")]];

// Defines a Container (objects that are created/destroyed together).
struct Container {
    u32 num_objects;
    u32 object_oids[num_objects];
} [[name("Container")]];


// Defines a key-value pair associated with a frame.
struct FrameKey {
    CString key;
    u32 type; // 0 for int, 1 for string
    if (type == 0) {
        u32 int_value;
    } else {
        CString string_value;
    }
} [[name("FrameKey")]];

// Represents an instance of an object placed in a layer.
struct ObjectInstance {
    u32 ignored_identifier;
    s32 x;
    s32 y;
    u32 width;
    u32 height;
    float angle;
    u32 color_filter [[color("FF6B6B")]]; // D3DCOLOR (ARGB)
    u32 plugin_id;
    u32 instance_id;
    u32 object_type_id;
    
    u32 num_initial_vars;
    CString initial_vars[num_initial_vars];
    
    u32 extra_data_size;
    u8 extra_data[extra_data_size] [[color("FF6B6B")]];
} [[name("ObjectInstance")]];

// Represents a single layer within a frame.
struct Layer {
    u32 layer_id;
    CString name;
    u8 layer_type;
    u32 color_filter [[color("FF6B6B")]];
    float opacity_factor; // opacity = value * 100.0
    float angle;
    float scroll_x_factor;
    float scroll_y_factor;
    float scroll_x_offset;
    float scroll_y_offset;
    float zoom_x_factor;
    float zoom_y_factor;
    float zoom_x_offset;
    float zoom_y_offset;
    u8 clear_background;
    u32 background_color [[color("FF6B6B")]];
    u8 force_own_texture;
    u32 sampler_mode; // Enum LayerSampler
    u8 enable_3d;
    u8 clear_depth_buffer;
    
    u32 instance_count;
    ObjectInstance instances[instance_count] [[color("4ECDC4")]];
} [[name("Layer")]];

// Represents a single Frame/Layout in the game.
struct LevelFrame {
    u32 width;
    u32 height;
    CString name;
    u32 bg_color_ref [[color("C7F464")]];
    u8 unbounded_scrolling;
    u8 use_app_background;

    u32 num_keys;
    FrameKey keys[num_keys];
    
    u32 num_layers;
    Layer layers[num_layers] [[color("C7F464")]];
    
    u32 num_image_handles;
    u32 used_image_handles[num_image_handles];
    
    u32 texture_loading_mode;
} [[name("LevelFrame")]];

struct AnimationFrame {
    float timeFactor;
    u32 imageHandle;
} [[name("AnimationFrame")]];

struct AnimationNode {
    u32 handle;
    CString name;
    CString tagId;
    float speed;
    u8 isAngle;
    float angle;
    u32 repeatCount;
    u32 repeatToFrame;
    u32 isPingpong;
    
    u32 numFrames;
    AnimationFrame frames[numFrames];
    
    // Recursive call for sub-animations
    u32 numSubAnimations;
    AnimationNode subAnimations[numSubAnimations];
} [[name("Animation")]];

struct AnimationBlock {
    u32 numAnimations;
    AnimationNode animations[numAnimations];
} [[name("AnimationBlock")]];


// The root structure of the LEVELBLOCK resource.
struct LevelBlock {
    u32 num_object_types;
    ObjectType object_types[num_object_types];

    u32 num_movements;
    MovementType movements[num_movements];

    u32 num_traits;
    Trait traits[num_traits];

    u32 num_families;
    Family families[num_families];

    u32 num_containers;
    Container containers[num_containers];

    u32 num_frames [[color("FF6B6B")]];
    LevelFrame frames[num_frames];

    // Check if there is AnimationNode data following the frames.
    AnimationBlock animationBank [[color("FFE66D")]];
    
} [[name("LevelBlock")]];


#pragma pattern_limit 531072

// Apply the pattern to the start of the file.
LevelBlock levelblock @ 0x00;