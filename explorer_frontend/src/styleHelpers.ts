import type { StyleObject } from "styletron-react";

export const mobileMaxScreenSize = 768;
export const tabletMaxScreenSize = 1440;
export const mediumMaxScreenSize = 1920;

export const getMobileStyles = (styles: StyleObject) => ({
  [`@media screen and (max-width: ${mobileMaxScreenSize}px)`]: {
    ...styles,
  },
});

export const getTabletStyles = (styles: StyleObject) => ({
  [`@media screen and (min-width: ${mobileMaxScreenSize + 1}px) and (max-width: ${tabletMaxScreenSize}px)`]:
  {
    ...styles,
  },
});

export const getDesktopStyles = (styles: StyleObject) => ({
  [`@media screen and (min-width: ${tabletMaxScreenSize + 1}px)`]: {
    ...styles,
  },
});

export const scrollableContentStyles: StyleObject = {
  width: "100%",
  ...getMobileStyles({
    overflow: "hidden",
  }),
  ...getTabletStyles({
    overflowX: "auto" as const,
  }),
  ...getDesktopStyles({
    overflowX: "auto" as const,
  }),
};
