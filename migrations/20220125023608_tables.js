/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
 exports.up = async function(knex) {
    await knex.schema.createTable("users", table => {
        table.increments()
        table.string("first_name")
        table.string("last_name")
        table.string("username")
        table.string("password")
        table.string("salt")
    })
  
    await knex.schema.createTable("posts", table => {
        table.increments()
        table.integer("userid")
        table.string("title")
        table.string("content", 1000)
        table.foreign("userid").references("users.id")
    })
  };
  
  /**
   * @param { import("knex").Knex } knex
   * @returns { Promise<void> }
   */
  exports.down = function(knex) {
    
  };
