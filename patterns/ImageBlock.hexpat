#pragma description Imageblock binary format

#pragma endian little

import std.mem;

struct ImagePoint {
    u32 x;
    u32 y;
    u32 name_length;
    char name[name_length];
} [[name("ImagePoint")]];

struct CollisionMask {
    u32 width;
    u32 height;
    u32 pitch;
    if (pitch * height > 0) {
        u8 mask_data[pitch * height];
    }
} [[name("CollisionMask")]];

struct ImageEntry {
    u32 image_handle [[comment("Image handle/ID")]];
    u32 hotspot_x [[comment("Hotspot X coordinate")]];
    u32 hotspot_y [[comment("Hotspot Y coordinate")]];
    
    u32 action_count [[comment("Number of action points")]];
    ImagePoint action_points[action_count] [[comment("Action points")]];
    
    u32 image_data_size [[comment("PNG file size in bytes")]];
    u8 png_data[image_data_size] [[comment("PNG image data"), color("FF6B6B")]];
    
    CollisionMask collision_mask [[comment("Collision mask data")]];
} [[name("Image")]];

struct ImageBlock {
    u32 num_images [[comment("Total number of images"), color("4ECDC4")]];
    ImageEntry images[num_images] [[comment("Image entries")]];
} [[name("ImageBlock")]];

ImageBlock imageblock @ 0x00;