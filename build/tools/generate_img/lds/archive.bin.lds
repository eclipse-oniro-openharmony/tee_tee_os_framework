/*
 * Packing everything under archive_ar
 */

SECTIONS
{
    .archive_ar :
    {
        *(.data)
    }
}
