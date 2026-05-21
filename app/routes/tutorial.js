const express = require("express");
const {
    environmentalScripts
} = require("../../config/config");

const router = express.Router();

router.get("/", (req, res) => {
    "use strict";
    return res.render("tutorial/a1", {
        environmentalScripts
    });
});

const pages = [
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "a8",
    "a9",
    "a10",
    "redos",
    "ssrf"
];

// Create a whitelist set for faster lookup
const allowedPages = new Set(pages);

for(const page of pages) {
    router.get(`/${page}`, (req, res) => {
        "use strict";
        return res.render(`tutorial/${page}`, {
            environmentalScripts
        });
    });
}

// Fix for Template Injection - validate page parameter against whitelist
router.get("/:page", (req, res) => {
    "use strict";
    const { page } = req.params;
    
    // Only render if page is in the whitelist
    if (!allowedPages.has(page)) {
        return res.status(404).render("error-template", {
            message: "Tutorial page not found",
            environmentalScripts
        });
    }
    
    return res.render(`tutorial/${page}`, {
        environmentalScripts
    });
});

module.exports = router;
