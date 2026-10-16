-- @maronn-openid-connect/cli 0.13.0 で schema.sql の access_tokens に加わった acr 列。
-- schema.sql は CREATE TABLE IF NOT EXISTS なので、0001_init.sql で作った表には列が増えない。
-- acr はトークンに載せた acr（acr_values で要求された値）で、acr を決めなかったトークンでは NULL。
ALTER TABLE access_tokens ADD COLUMN acr VARCHAR(5000);
